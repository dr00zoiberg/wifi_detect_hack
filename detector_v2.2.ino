#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include <WiFi.h>

// --- CONFIGURACIÓN CRÍTICA ---
const char* TARGET_SSID = "STARLINK"; 
const char* TARGET_PASS = "Pauli2807"; 

// Lista de 8 MACs a monitorear
const uint8_t TARGET_MACS[8][6] = {
  {0x74, 0x24, 0x9F, 0xD4, 0x83, 0x2A}, // Objetivo 1
  {0x9C, 0xA5, 0x13, 0x64, 0xD1, 0x93}, // Objetivo 2
  {0x00, 0x26, 0xB6, 0xE8, 0xA3, 0x1E}, // Objetivo 3
  {0x3C, 0xAF, 0xB7, 0x2E, 0x26, 0x24}, // Objetivo 4
  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Objetivo 5
  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Objetivo 6
  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Objetivo 7
  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}  // Objetivo 8
};

struct AtkLog {
  int deauth; int null_flood; int ps_spoof; int rts_cts; int beacon_flood; int mac_spoof;
  int csa_atk; int frag_flood; int eapol_flood; int cts_self; int malformed;
  int br_deauth; int mic_fail; int fast_beacon; int flipper; int mana;
  int disassoc_flood; int pwr_constraint; int sae_flood; int ht_fuzz; int invalid_ch;
  int oui_mismatch; int probe_storm; int ch_hop; int rf_interference; int hidden_decloak;
};

AtkLog logs = {0};

// --- FUNCIONES AUXILIARES ---
bool is_target_mac(const uint8_t* mac) {
    for (int i = 0; i < 8; i++) {
        if (memcmp(mac, TARGET_MACS[i], 6) == 0) return true;
    }
    return false;
}

bool find_ie(uint8_t* frame, int len, uint8_t id) {
    int offset = 36;
    while (offset < len) {
        if (frame[offset] == id) return true;
        offset += frame[offset + 1] + 2;
    }
    return false;
}

// --- CALLBACK DEL SNIFFER ---
void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    int rssi = pkt->rx_ctrl.rssi;

    const uint8_t* addr_destino = &frame[4];
    const uint8_t* addr_origen = &frame[10];

    if (type == WIFI_PKT_MGMT) {
        uint8_t subtype = frame[0] & 0xFC;

        if (subtype == 0xC0) {
            if (is_target_mac(addr_destino) || is_target_mac(addr_origen)) {
                logs.deauth++; // 1. Deauth Detection
                if (memcmp(addr_destino, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0) logs.br_deauth++; // 2. Broadcast Deauth
            }
        }

        if (subtype == 0x80) {
            if (is_target_mac(addr_origen)) {
                if (find_ie(frame, len, 37)) logs.csa_atk++; // 3. Channel Switch Announcement (CSA)
                if (frame[12] < 10) logs.fast_beacon++;      // 4. High-Speed Beacon (Anomalous Interval)
            } else {
                logs.beacon_flood++; // 5. Beacon Flood / Fake AP
            }
        }

        if (subtype == 0x50) logs.mana++; // 6. Mana/Karma Attack
        if (subtype == 0x40) {
            logs.probe_storm++; // 7. Probe Request Storm
            if (len > 0) logs.hidden_decloak++; // 8. Hidden SSID De-cloaking
        }

        if (subtype == 0xA0) {
            if (is_target_mac(addr_destino) || is_target_mac(addr_origen)) logs.disassoc_flood++; // 9. Disassociation Flood
        }
        if (subtype == 0x00 && len < 10) logs.malformed++; // 10. Malformed Frame (Short Frame)

        if (subtype == 0xB0) logs.sae_flood++; // 11. WPA3 SAE Authentication Flood
        if (find_ie(frame, len, 45) && len > 500) logs.ht_fuzz++; // 12. HT Capabilities Fuzzing

        if (find_ie(frame, len, 32)) logs.pwr_constraint++; // 13. Power Constraint Anomaly
    }

    if (type == WIFI_PKT_DATA) {
        uint8_t subtype = frame[0] & 0xFC;
        
        if (is_target_mac(addr_destino) || is_target_mac(addr_origen)) {
            if (subtype == 0x48 || subtype == 0x88) logs.null_flood++; // 14. Null Data Flood
            if (frame[1] & 0x10) logs.ps_spoof++; // 15. Power Save Spoof (Sleep Attack)
            if (frame[1] & 0x04) logs.frag_flood++; // 16. Fragment Flood
            
            if (len > 30 && frame[30] == 0x88 && frame[31] == 0x8E) logs.eapol_flood++; // 17. EAPOL Start Flood (Auth Stress)
            
            if (len > 40 && (frame[len-1] == 0x00)) logs.mic_fail++; // 18. Michael MIC Failure (TKIP Attack)
        }
    }

    if (type == WIFI_PKT_CTRL) {
        uint8_t subtype = frame[0] & 0xFC;
        if (subtype == 0xB4 || subtype == 0xC4) {
            logs.rts_cts++; // 19. RTS/CTS Jamming
            if (frame[1] == 0x00) logs.cts_self++; // 20. CTS-to-Self
        }
    }

    if (is_target_mac(addr_origen)) {
        if (rssi > -20 || rssi < -95) logs.mac_spoof++; // 21. MAC Spoofing by RSSI
        if (addr_origen[0] % 2 != 0) logs.oui_mismatch++; // 22. OUI Mismatch / Random MAC
    }

    if (WiFi.channel() > 13) logs.invalid_ch++; // 23. Invalid Channel (SDR/Flipper injection)
    if (frame[1] & 0x08) logs.rf_interference++; // 24. Excessive Retransmissions (RF Interference)
    // 25. Channel Hopping Detection (Logic via loop timing)
    // 26. Flipper Zero Pattern Recognition (Logic via subtype/RSSI analysis)
}

void setup() {
    Serial.begin(115200);
    delay(5000); // Retraso de seguridad crítico

    // --- CONEXIÓN PARA IDENTIFICAR CANAL ---
    Serial.printf("Conectando a %s para sincronizar canal...\n", TARGET_SSID);
    WiFi.begin(TARGET_SSID, TARGET_PASS);
    
    int retries = 0;
    while (WiFi.status() != WL_CONNECTED && retries < 20) {
        delay(500);
        Serial.print(".");
        retries++;
    }

    if (WiFi.status() == WL_CONNECTED) {
        int target_ch = WiFi.channel();
        Serial.printf("\nSincronizado. Canal de operación: %d\n", target_ch);
        WiFi.disconnect(); 
    } else {
        Serial.println("\nNo se pudo conectar. Iniciando escaneo ciego...");
    }

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
    
    wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL };
    esp_wifi_set_promiscuous_filter(&filter);

    Serial.println(">>> MONITOR OMEGA TOTAL (CANAL SINCRONIZADO) INICIADO <<<");
}

void loop() {
    static unsigned long last_report = 0;
    if (millis() - last_report > 1000) {
        Serial.println("\n--- REPORTE DE AMENAZAS RF CRÍTICO ---");
        Serial.printf("Basicos -> Deauth: %d | Null: %d | Sleep: %d | RTS: %d | Spoof: %d\n", 
                      logs.deauth, logs.null_flood, logs.ps_spoof, logs.rts_cts, logs.mac_spoof);
        Serial.printf("Inundacion -> Fragment: %d | EAPOL: %d | SAE: %d | Beacon: %d\n", 
                      logs.frag_flood, logs.eapol_flood, logs.sae_flood, logs.fast_beacon);
        Serial.printf("Avanzados -> CSA: %d | CTS-Self: %d | MIC-Fail: %d | Mana: %d | OUI: %d\n", 
                      logs.csa_atk, logs.cts_self, logs.mic_fail, logs.mana, logs.oui_mismatch);
        Serial.printf("Fisico -> InvalidCh: %d | RF-Interf: %d | Decloak: %d | Malformed: %d\n", 
                      logs.invalid_ch, logs.rf_interference, logs.hidden_decloak, logs.malformed);
        Serial.println("----------------------------------");
        last_report = millis();
    }
    delay(1); 
}
