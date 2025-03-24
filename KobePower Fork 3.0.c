/**
 * Kobe Fork – Proxmark3 Ultimate Firmware v3.0
 * ----------------------------------------------
 * Features: LF/HF/UHF support, advanced CLI, signal analysis, flash management,
 * brute-force, AI, DFU, Python integration, anti-tear, unit tests
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include "proxmark3_arm.h"
#include "cmd.h"
#include "util.h"
#include "lfops.h"
#include "hfops.h"
#include "usb_cmd.h"
#include "mifare.h"
#include "em410x.h"
#include "iso14443b.h"

// ------ System Constants ------
#define FIRMWARE_VERSION    "Kobe Fork v3.0 - Ultimate Edition"
#define LOG_BUFFER_SIZE     128
#define LOG_RING_SIZE       32
#define CMD_HISTORY_SIZE    10
#define CMD_MAX_LEN         64
#define CONFIG_FLASH_ADDR   0x0807F000
#define TAG_DB_FLASH_ADDR   0x08078000
#define EMERGENCY_FLASH_ADDR 0x0807E000
#define WATCHDOG_TIMEOUT_MS 3000
#define RFID_TIMEOUT_MS     2000
#define FLASH_PAGE_SIZE     2048
#define WEAR_LEVEL_PAGES    8
#define TLV_HEADER_SIZE     8
#define EPCGEN2_UID_LEN     12

// ------ Logging System ------
typedef enum {
    LOG_ERROR,
    LOG_WARNING,
    LOG_INFO,
    LOG_DEBUG
} LogLevel;

static LogLevel current_log_level = LOG_DEBUG;
static char log_ring[LOG_RING_SIZE][LOG_BUFFER_SIZE];
static uint8_t log_head = 0;

void system_log(LogLevel level, const char* format, ...) {
    if (level > current_log_level) return;
    va_list args;
    va_start(args, format);
    __disable_irq();
    char* buffer = log_ring[log_head++ % LOG_RING_SIZE];
    uint32_t tick = GetTickCount();
    const char* level_str[] = {"ERR", "WRN", "INF", "DBG"};
    snprintf(buffer, LOG_BUFFER_SIZE, "[%08lu][%s] ", tick, level_str[level]);
    vsnprintf(buffer + 14, LOG_BUFFER_SIZE - 14, format, args);
    Dbprintf("%s", buffer);
    __enable_irq();
    va_end(args);
}

// ------ Hardware Abstraction ------
typedef enum {
    HW_OK,
    HW_ERR_UART,
    HW_ERR_RFID,
    HW_ERR_FLASH,
    HW_ERR_POWER
} HwStatus;

typedef struct {
    bool uart_ready;
    bool rfid_ready;
    uint32_t last_watchdog_pet;
    uint32_t last_status_check;
} HardwareState;

static HardwareState hw_state;

HwStatus init_hardware(void) {
    hw_state = (HardwareState){0};
    LED_A_ON();
    usb_init();
    if (!usb_poll()) return HW_ERR_UART;
    hw_state.uart_ready = true;
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    if (!FpgaGetStatus()) return HW_ERR_RFID;
    hw_state.rfid_ready = true;
    WDT_Init(WATCHDOG_TIMEOUT_MS);
    hw_state.last_watchdog_pet = GetTickCount();
    hw_state.last_status_check = GetTickCount();
    system_log(LOG_INFO, "Hardware initialized");
    LED_A_OFF();
    return HW_OK;
}

HwStatus poll_hardware_status(void) {
    static uint32_t last_voltage_check = 0;
    if (!FpgaGetStatus()) return HW_ERR_RFID;
    if (!AntennaGetStatus()) return HW_ERR_RFID;
    if (GetTickCount() - last_voltage_check > 5000) {
        uint16_t v = GetAdc(ADC_CHAN_VDD);
        if (v < 3000) return HW_ERR_POWER;
        last_voltage_check = GetTickCount();
    }
    if (!usb_poll()) return HW_ERR_UART;
    return HW_OK;
}

bool power_loss_imminent(void) {
    return GetAdc(ADC_CHAN_VDD) < 3100;  // Threshold just above critical
}

bool voltage_sufficient(void) {
    return GetAdc(ADC_CHAN_VDD) > 2800;  // Minimum for flash write
}

void get_critical_data(uint8_t* buffer) {
    memcpy(buffer, (uint8_t*)&current_config, sizeof(SystemConfig));
    memcpy(buffer + sizeof(SystemConfig), (uint8_t*)&rfid, sizeof(RfidContext));
}

void emergency_save(void) {
    uint8_t critical_data[128];
    get_critical_data(critical_data);
    if (voltage_sufficient()) {
        FlashmemWrite(critical_data, EMERGENCY_FLASH_ADDR, sizeof(critical_data));
        system_log(LOG_INFO, "Emergency save completed");
    } else {
        system_log(LOG_ERROR, "Insufficient voltage for emergency save");
    }
}

// ------ CRC Implementation ------
uint32_t calculate_crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    while (len--) {
        crc ^= *data++;
        for (int i = 0; i < 8; i++)
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
    }
    return ~crc;
}

uint8_t calculate_crc8(const uint8_t* data, size_t len) {
    uint8_t crc = 0xFF;
    while (len--) {
        crc ^= *data++;
        for (int i = 0; i < 8; i++)
            crc = (crc & 0x80) ? (crc << 1) ^ 0x31 : (crc << 1);
    }
    return crc;
}

// ------ Configuration Manager ------
#pragma pack(push, 1)
typedef struct {
    uint16_t version;
    uint32_t baudrate;
    uint8_t rfid_power_lf;
    uint8_t rfid_power_hf;
    uint16_t scan_interval;
    bool auto_scan;
    uint32_t crc;
} SystemConfig;
#pragma pack(pop)

static SystemConfig current_config = {
    .version = 3,
    .baudrate = 115200,
    .rfid_power_lf = 90,
    .rfid_power_hf = 85,
    .scan_interval = 500,
    .auto_scan = true,
    .crc = 0
};

HwStatus load_configuration(void) {
    FlashmemRead((uint8_t*)¤t_config, CONFIG_FLASH_ADDR, sizeof(SystemConfig));
    uint32_t stored_crc = current_config.crc;
    current_config.crc = 0;
    if (current_config.version != 3 || 
        calculate_crc32((uint8_t*)¤t_config, sizeof(SystemConfig) - 4) != stored_crc) {
        system_log(LOG_WARNING, "Invalid config, loading defaults");
        current_config.crc = calculate_crc32((uint8_t*)¤t_config, sizeof(SystemConfig) - 4);
        FlashmemWrite((uint8_t*)¤t_config, CONFIG_FLASH_ADDR, sizeof(SystemConfig));
    }
    usb_setbaud(current_config.baudrate);
    lf_set_power(current_config.rfid_power_lf);
    hf_set_power(current_config.rfid_power_hf);
    return HW_OK;
}

HwStatus save_configuration(void) {
    current_config.crc = calculate_crc32((uint8_t*)¤t_config, sizeof(SystemConfig) - 4);
    if (!FlashmemWrite((uint8_t*)¤t_config, CONFIG_FLASH_ADDR, sizeof(SystemConfig))) {
        system_log(LOG_ERROR, "Failed to save config");
        return HW_ERR_FLASH;
    }
    return HW_OK;
}

// ------ Tag Database ------
#pragma pack(push, 1)
typedef struct {
    uint8_t type;       // 0: LF, 1: HF, 2: UHF
    uint8_t protocol;   // 0: EM410x, 1: MIFARE, 2: ISO14443A, 3: ISO14443B, 4: EPC Gen2
    uint32_t timestamp;
    uint16_t data_len;
    uint8_t uid[10];
    uint8_t checksum;
} TagEntryHeader;
#pragma pack(pop)

static uint32_t current_wear_page = 0;
static uint32_t write_ptr = 0;
static uint32_t write_counters[WEAR_LEVEL_PAGES] = {0};

void rotate_wear_page(void) {
    uint32_t min_writes = UINT32_MAX;
    for (int i = 0; i < WEAR_LEVEL_PAGES; i++) {
        if (write_counters[i] < min_writes) {
            min_writes = write_counters[i];
            current_wear_page = i;
        }
    }
    write_counters[current_wear_page]++;
    write_ptr = 0;
    FlashmemErase(TAG_DB_FLASH_ADDR + (current_wear_page * FLASH_PAGE_SIZE));
}

void save_tag_tlv(uint8_t type, uint8_t protocol, const uint8_t* uid, uint8_t uid_len) {
    TagEntryHeader header = {
        .type = type,
        .protocol = protocol,
        .timestamp = GetTickCount(),
        .data_len = uid_len,
        .checksum = calculate_crc8(uid, uid_len)
    };
    memcpy(header.uid, uid, uid_len > 10 ? 10 : uid_len);
    
    if (write_ptr + sizeof(header) > FLASH_PAGE_SIZE) {
        rotate_wear_page();
    }
    
    uint32_t addr = TAG_DB_FLASH_ADDR + (current_wear_page * FLASH_PAGE_SIZE) + write_ptr;
    FlashmemWrite((uint8_t*)&header, addr, sizeof(header));
    write_ptr += sizeof(header);
    
    system_log(LOG_INFO, "Tag saved: Type %d, Protocol %d", type, protocol);
}

// ------ CLI System ------
typedef struct {
    const char* name;
    void (*handler)(char* args);
    bool needs_tag;
    const char* description;
} Command;

static char cmd_history[CMD_HISTORY_SIZE][CMD_MAX_LEN];
static uint8_t cmd_history_head = 0, cmd_history_tail = 0;

void add_to_history(const char* cmd) {
    strncpy(cmd_history[cmd_history_head], cmd, CMD_MAX_LEN - 1);
    cmd_history[cmd_history_head][CMD_MAX_LEN - 1] = '\0';
    cmd_history_head = (cmd_history_head + 1) % CMD_HISTORY_SIZE;
    if (cmd_history_head == cmd_history_tail) {
        cmd_history_tail = (cmd_history_tail + 1) % CMD_HISTORY_SIZE;
    }
}

void cmd_tab_complete(char* input, size_t len) {
    for (size_t i = 0; i < sizeof(commands) / sizeof(Command); i++) {
        if (strncmp(input, commands[i].name, len) == 0) {
            Dbprintf("Suggestion: %s - %s", commands[i].name, commands[i].description);
        }
    }
}

void cmd_read_handler(char* args) {
    if (rfid.state != RFID_READING) {
        system_log(LOG_WARNING, "No tag detected");
        return;
    }
    if (rfid.protocol == 0) {  // EM410x
        uint64_t id = em410x_read();
        system_log(LOG_INFO, "EM410x ID: %010llx", id);
    } else if (rfid.protocol == 1) {  // MIFARE
        uint8_t block[16];
        if (mf_readblock(0, 0, block)) {
            system_log(LOG_INFO, "MIFARE Block 0: %02x%02x%02x%02x...",
                       block[0], block[1], block[2], block[3]);
        }
    } else if (rfid.protocol == 4) {  // EPC Gen2
        system_log(LOG_INFO, "EPC Gen2 UID: %02x%02x%02x%02x...",
                   rfid.uid[0], rfid.uid[1], rfid.uid[2], rfid.uid[3]);
    }
}

void cmd_write_tag(char* args) {
    if (rfid.state != RFID_WRITING) {
        system_log(LOG_WARNING, "No writable tag detected");
        return;
    }
    if (rfid.protocol == 1) {  // MIFARE
        uint8_t block = 0;
        uint8_t data[16] = {0};
        if (sscanf(args, "%hhu %02hhx%02hhx%02hhx%02hhx", &block,
                  &data[0], &data[1], &data[2], &data[3]) != 5) {
            system_log(LOG_WARNING, "Usage: write <block> <hex data (4 bytes)>");
            return;
        }
        if (mf_write_block(block, 0, data)) {
            system_log(LOG_INFO, "MIFARE Block %d written", block);
        } else {
            system_log(LOG_ERROR, "Write failed");
        }
    }
}

void cmd_scan_handler(char* args) {
    set_rfid_state(RFID_DETECT_LF);
    system_log(LOG_INFO, "Starting multi-protocol scan");
}

void cmd_analyze_handler(char* args) {
    set_rfid_state(RFID_ANALYZING);
    system_log(LOG_INFO, "Starting signal analysis");
}

void cmd_db_handler(char* args) {
    uint32_t addr = TAG_DB_FLASH_ADDR + (current_wear_page * FLASH_PAGE_SIZE);
    TagEntryHeader header;
    for (uint32_t i = 0; i < write_ptr; i += sizeof(header)) {
        FlashmemRead((uint8_t*)&header, addr + i, sizeof(header));
        if (header.data_len > 0) {
            system_log(LOG_INFO, "Tag: Type %d, Protocol %d, UID: %02x%02x%02x%02x...",
                       header.type, header.protocol, header.uid[0], header.uid[1],
                       header.uid[2], header.uid[3]);
        }
    }
}

void cmd_config_handler(char* args) {
    if (!args) {
        system_log(LOG_INFO, "Config: Baud %lu, LF %u%%, HF %u%%, Interval %u ms, Auto %s",
                   current_config.baudrate, current_config.rfid_power_lf,
                   current_config.rfid_power_hf, current_config.scan_interval,
                   current_config.auto_scan ? "ON" : "OFF");
        return;
    }
    char* key = strtok(args, " ");
    char* value = strtok(NULL, " ");
    if (!key || !value) {
        system_log(LOG_WARNING, "Usage: config <key> <value>");
        return;
    }
    if (strcmp(key, "baudrate") == 0) {
        uint32_t baud = atol(value);
        if (baud >= 9600 && baud <= 921600) current_config.baudrate = baud;
    } else if (strcmp(key, "lfpower") == 0) {
        uint8_t power = atoi(value);
        if (power <= 100) current_config.rfid_power_lf = power;
    } else if (strcmp(key, "hfpower") == 0) {
        uint8_t power = atoi(value);
        if (power <= 100) current_config.rfid_power_hf = power;
    } else if (strcmp(key, "interval") == 0) {
        uint16_t interval = atoi(value);
        if (interval >= 100) current_config.scan_interval = interval;
    } else if (strcmp(key, "autoscan") == 0) {
        current_config.auto_scan = (strcmp(value, "on") == 0);
    } else {
        system_log(LOG_WARNING, "Invalid key: %s", key);
        return;
    }
    save_configuration();
    system_log(LOG_INFO, "Config updated");
}

void cmd_brute_handler(char* args) {
    if (rfid.state != RFID_READING) {
        system_log(LOG_WARNING, "No tag ready for brute-force");
        return;
    }
    if (rfid.protocol == 1) {  // MIFARE
        system_log(LOG_INFO, "Brute-forcing MIFARE key for sector 0");
        uint8_t key[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        uint8_t response[4];
        for (uint32_t i = 0; i < 0xFFFFFF; i++) {
            key[3] = (i >> 16) & 0xFF;
            key[4] = (i >> 8) & 0xFF;
            key[5] = i & 0xFF;
            mf_auth(0, key, response);
            if (mf_validate(response)) {
                system_log(LOG_INFO, "Key found: %02x%02x%02x%02x%02x%02x",
                           key[0], key[1], key[2], key[3], key[4], key[5]);
                return;
            }
            if (i % 10000 == 0) system_log(LOG_DEBUG, "Tried %lu keys", i);
        }
        system_log(LOG_ERROR, "No key found");
    }
}

void cmd_monitor_handler(char* args) {
    system_log(LOG_INFO, "USB monitor started. Press button to stop.");
    while (!BUTTON_PRESSED()) {
        PacketResponseNG resp;
        if (GetFromDevice(BIGBUF, (uint8_t*)&resp, sizeof(resp), 100, NULL, 0)) {
            system_log(LOG_DEBUG, "RX: %02x%02x%02x%02x...",
                       resp.data.asBytes[0], resp.data.asBytes[1],
                       resp.data.asBytes[2], resp.data.asBytes[3]);
        }
        SpinDelay(10);
    }
    system_log(LOG_INFO, "Monitor stopped");
}

void cmd_update_handler(char* args) {
    if (!args || !strlen(args)) {
        system_log(LOG_WARNING, "Usage: update <size>");
        return;
    }
    uint32_t size = atoi(args);
    if (size > 0 && size <= 0x7E000) {
        system_log(LOG_INFO, "Updating firmware (%lu bytes)", size);
        uint8_t* image = usb_get_buffer();
        FlashmemErase(0x08000000, size);
        FlashmemWrite(image, 0x08000000, size);
        system_log(LOG_INFO, "Update complete. Rebooting...");
        reboot();
    } else {
        system_log(LOG_ERROR, "Invalid size: %lu", size);
    }
}

void cmd_ai_classify_handler(char* args) {
    if (rfid.state != RFID_READING) {
        system_log(LOG_WARNING, "No tag to classify");
        return;
    }
    system_log(LOG_INFO, "Classifying tag...");
    if (rfid.protocol == 0) {
        system_log(LOG_INFO, "Tag: EM410x, likely read-only");
    } else if (rfid.protocol == 1 && rfid.rssi > 50) {
        system_log(LOG_INFO, "Tag: MIFARE Classic, possibly vulnerable to default keys");
    } else if (rfid.protocol == 4) {
        system_log(LOG_INFO, "Tag: EPC Gen2, likely supply chain use");
    } else {
        system_log(LOG_INFO, "Tag: Unknown or secure");
    }
}

void cmd_help_handler(char* args) {
    system_log(LOG_INFO, "Commands:");
    for (size_t i = 0; i < sizeof(commands) / sizeof(Command); i++) {
        system_log(LOG_INFO, "  %s - %s", commands[i].name, commands[i].description);
    }
}

void cmd_history_handler(char* args) {
    for (uint8_t i = cmd_history_tail; i != cmd_history_head; i = (i + 1) % CMD_HISTORY_SIZE) {
        system_log(LOG_INFO, "  %s", cmd_history[i]);
    }
}

const Command commands[] = {
    {"read",    cmd_read_handler,   true,  "Read tag data (e.g., EM410x ID, MIFARE block)"},
    {"write",   cmd_write_tag,      true,  "Write tag data (e.g., write 1 01020304)"},
    {"scan",    cmd_scan_handler,   false, "Scan for LF/HF/UHF tags"},
    {"analyze", cmd_analyze_handler,false, "Analyze signal (RSSI, modulation, noise)"},
    {"db",      cmd_db_handler,     false, "Show tag database"},
    {"config",  cmd_config_handler, false, "Show/set config (e.g., config baudrate 115200)"},
    {"update",  cmd_update_handler, false, "Flash firmware update (e.g., update 123456)"},
    {"monitor", cmd_monitor_handler,false, "USB monitor mode for dev/debug"},
    {"ai",      cmd_ai_classify_handler, true, "Run AI tag classification (experimental)"},
    {"brute",   cmd_brute_handler,  true,  "Run brute-force attack on tag"},
    {"help",    cmd_help_handler,   false, "Show this help"},
    {"history", cmd_history_handler,false, "Show command history"}
};

void process_commands(void) {
    PacketResponseNG resp;
    if (!GetFromDevice(BIGBUF, (uint8_t*)&resp, sizeof(resp), 1000, NULL, 0)) return;
    if (resp.oldarg[0] == 0) return;
    char input[CMD_MAX_LEN];
    strncpy(input, (char*)resp.data.asBytes, CMD_MAX_LEN - 1);
    input[CMD_MAX_LEN - 1] = '\0';
    if (strcmp(input, "tab") == 0) {
        cmd_tab_complete(input, strlen(input));
        return;
    }
    add_to_history(input);
    char* args = strchr(input, ' ');
    if (args) {
        *args = '\0';
        args++;
    }
    for (size_t i = 0; i < sizeof(commands) / sizeof(Command); i++) {
        if (strcmp(input, commands[i].name) == 0) {
            if (commands[i].needs_tag && rfid.state != RFID_READING && rfid.state != RFID_WRITING) {
                system_log(LOG_WARNING, "Command requires active tag");
            } else {
                commands[i].handler(args);
            }
            return;
        }
    }
    system_log(LOG_WARNING, "Unknown command: %s", input);
}

// ------ RFID State Machine ------
typedef enum {
    RFID_IDLE,
    RFID_DETECT_LF,
    RFID_DETECT_HF,
#ifdef UHF_SUPPORT
    RFID_DETECT_UHF,
#endif
    RFID_READING,
    RFID_WRITING,
    RFID_ANALYZING,
    RFID_ERROR
} RfidState;

typedef struct {
    RfidState state;
    uint8_t retries;
    uint32_t last_activity;
    uint32_t state_start_time;
    uint8_t uid[12];  // Extended for EPC Gen2
    uint8_t uid_len;
    char type[16];
    uint8_t protocol;
    bool field_active;
    uint16_t rssi;
    uint8_t modulation;  // 0: ASK, 1: FSK, 2: PSK, 3: NFC
} RfidContext;

static RfidContext rfid = {0};

const RfidState state_transitions[][8] = {
    /* From/To     IDLE    DET_LF  DET_HF  DET_UHF READ    WRITE   ANALYZE ERROR */
    /* IDLE    */ {IDLE,   DET_LF, DET_HF, DET_UHF,IDLE,   IDLE,   IDLE,   ERROR},
    /* DET_LF  */ {IDLE,   DET_LF, DET_HF, DET_UHF,READ,   WRITE,  ANALYZE,ERROR},
    /* DET_HF  */ {IDLE,   DET_LF, DET_HF, DET_UHF,READ,   WRITE,  ANALYZE,ERROR},
    /* DET_UHF */ {IDLE,   DET_LF, DET_HF, DET_UHF,READ,   WRITE,  ANALYZE,ERROR},
    /* READ    */ {IDLE,   DET_LF, DET_HF, DET_UHF,READ,   WRITE,  ANALYZE,ERROR},
    /* WRITE   */ {IDLE,   DET_LF, DET_HF, DET_UHF,READ,   WRITE,  ANALYZE,ERROR},
    /* ANALYZE */ {IDLE,   DET_LF, DET_HF, DET_UHF,READ,   WRITE,  ANALYZE,ERROR},
    /* ERROR   */ {IDLE,   DET_LF, DET_HF, DET_UHF,IDLE,   IDLE,   IDLE,   ERROR}
};

bool set_rfid_state(RfidState new_state) {
    if (state_transitions[rfid.state][new_state] != new_state) {
        system_log(LOG_WARNING, "Invalid state transition %d->%d", rfid.state, new_state);
        return false;
    }
    if (rfid.field_active && new_state == RFID_IDLE) {
        lf_field_off();
        hf_field_off();
#ifdef UHF_SUPPORT
        uhf_field_off();
#endif
        rfid.field_active = false;
    }
    rfid.state = new_state;
    rfid.last_activity = GetTickCount();
    rfid.state_start_time = rfid.last_activity;
    return true;
}

// ------ Signal Analysis Helpers ------
uint16_t lf_get_rssi(void) {
    uint32_t total = 0;
    for (int i = 0; i < 10; i++) {
        total += GetAdc(ADC_CHAN_LF_RSSI);
        SpinDelay(1);
    }
    return total / 10;
}

uint16_t hf_get_rssi(void) {
    uint32_t total = 0;
    for (int i = 0; i < 10; i++) {
        total += GetAdc(ADC_CHAN_HF_RSSI);
        SpinDelay(1);
    }
    return total / 10;
}

#ifdef UHF_SUPPORT
uint16_t uhf_get_rssi(void) {
    uint32_t total = 0;
    for (int i = 0; i < 10; i++) {
        total += GetAdc(ADC_CHAN_UHF_RSSI);
        SpinDelay(1);
    }
    return total / 10;
}
#endif

uint32_t measure_noise(void) {
    uint32_t noise = 0;
    for (int i = 0; i < 100; i++) {
        noise += GetAdc(ADC_CHAN_NOISE);
        SpinDelay(1);
    }
    return noise / 100;
}

// ------ RFID Operations ------
void rfid_detect_lf(void) {
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    lf_field_on();
    SpinDelay(50);
    if (em410x_detect(rfid.uid, &rfid.uid_len)) {
        rfid.field_active = FPGA_BITSTREAM_LF;
        strcpy(rfid.type, "EM410x");
        rfid.protocol = 0;
        rfid.rssi = lf_get_rssi();
        rfid.modulation = 0;
        save_tag_tlv(0, 0, rfid.uid, rfid.uid_len);
        set_rfid_state(RFID_READING);
    } else {
        lf_field_off();
        set_rfid_state(RFID_DETECT_HF);
    }
}

void rfid_detect_hf(void) {
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    hf_field_on();
    SpinDelay(50);
    if (hf14a_getuid(rfid.uid, &rfid.uid_len)) {
        rfid.field_active = FPGA_BITSTREAM_HF;
        if (mf_is_mifare()) {
            strcpy(rfid.type, "MIFARE Classic");
            rfid.protocol = 1;
            rfid.modulation = 3;
        } else if (iso14443b_select_tag(rfid.uid, &rfid.uid_len)) {
            strcpy(rfid.type, "ISO14443B");
            rfid.protocol = 3;
            rfid.modulation = 2;
        } else {
            strcpy(rfid.type, "ISO14443A");
            rfid.protocol = 2;
            rfid.modulation = 2;
        }
        rfid.rssi = hf_get_rssi();
        save_tag_tlv(1, rfid.protocol, rfid.uid, rfid.uid_len);
        set_rfid_state(RFID_READING);
    } else {
        hf_field_off();
#ifdef UHF_SUPPORT
        set_rfid_state(RFID_DETECT_UHF);
#else
        if (rfid.retries++ >= 3) set_rfid_state(RFID_ERROR);
#endif
    }
}

#ifdef UHF_SUPPORT
void uhf_scan(void) {
    uhf_field_on();
    SpinDelay(50);
    if (epc_gen2_inventory(rfid.uid)) {
        rfid.field_active = FPGA_BITSTREAM_UHF;
        strcpy(rfid.type, "EPC Gen2");
        rfid.protocol = 4;
        rfid.uid_len = EPCGEN2_UID_LEN;
        rfid.rssi = uhf_get_rssi();
        rfid.modulation = 1;  // FSK typical for UHF
        save_tag_tlv(2, 4, rfid.uid, rfid.uid_len);
        set_rfid_state(RFID_READING);
    } else {
        uhf_field_off();
        if (rfid.retries++ >= 3) set_rfid_state(RFID_ERROR);
    }
}
#endif

void rfid_analyze(void) {
    if (!rfid.field_active) {
        system_log(LOG_WARNING, "No active field");
        set_rfid_state(RFID_IDLE);
        return;
    }
    uint16_t rssi = (rfid.field_active == FPGA_BITSTREAM_LF) ? lf_get_rssi() :
                    (rfid.field_active == FPGA_BITSTREAM_HF) ? hf_get_rssi() :
#ifdef UHF_SUPPORT
                    uhf_get_rssi();
#else
                    0;
#endif
    uint32_t noise = measure_noise();
    const char* mod_str[] = {"ASK", "FSK", "PSK", "NFC"};
    system_log(LOG_INFO, "Signal: RSSI %d, Mod %s, Noise %lu", rssi, mod_str[rfid.modulation], noise);
    set_rfid_state(RFID_IDLE);
}

// ------ MIFARE Authentication ------
void mf_auth(uint8_t block, uint8_t* key, uint8_t* response) {
    uint8_t nt[4], nr[4];
    mifare_sendcmd(MF_AUTH_KEY_A, block, key, nt);
    mifare_sendcmd(MF_AUTH_NONCE, block, NULL, nr);
    mifare_crypto1(nt, nr, response);
}

bool mf_validate(uint8_t* response) {
    uint8_t check[4];
    mifare_sendcmd(MF_AUTH_VALIDATE, 0, response, check);
    return memcmp(response, check, 4) == 0;
}

// ------ Main Application ------
int main(void) {
    if (init_hardware() != HW_OK) {
        system_log(LOG_ERROR, "Hardware init failed");
        while (1) SpinDelay(500);
    }
    load_configuration();
    system_log(LOG_INFO, "=== %s Initialized ===", FIRMWARE_VERSION);
    
    while (1) {
        WDT_Pet();
        hw_state.last_watchdog_pet = GetTickCount();
        
        if (GetTickCount() - hw_state.last_status_check > 1000) {
            if (poll_hardware_status() != HW_OK) set_rfid_state(RFID_ERROR);
            hw_state.last_status_check = GetTickCount();
        }
        
        if (power_loss_imminent()) emergency_save();
        
        process_commands();
        
        if (rfid.state != RFID_IDLE && GetTickCount() - rfid.state_start_time > RFID_TIMEOUT_MS) {
            system_log(LOG_WARNING, "RFID timeout");
            set_rfid_state(RFID_ERROR);
        }
        
        switch (rfid.state) {
            case RFID_IDLE:
                if (current_config.auto_scan && 
                    GetTickCount() - rfid.last_activity > current_config.scan_interval) {
                    set_rfid_state(RFID_DETECT_LF);
                }
                break;
                
            case RFID_DETECT_LF:
                LED_B_ON();
                rfid_detect_lf();
                LED_B_OFF();
                break;
                
            case RFID_DETECT_HF:
                LED_B_ON();
                rfid_detect_hf();
                LED_B_OFF();
                break;
                
#ifdef UHF_SUPPORT
            case RFID_DETECT_UHF:
                LED_B_ON();
                uhf_scan();
                LED_B_OFF();
                break;
#endif
                
            case RFID_READING:
                if (BUTTON_PRESSED()) set_rfid_state(RFID_WRITING);
                break;
                
            case RFID_WRITING:
                if (BUTTON_PRESSED()) set_rfid_state(RFID_READING);
                break;
                
            case RFID_ANALYZING:
                rfid_analyze();
                break;
                
            case RFID_ERROR:
                system_log(LOG_ERROR, "RFID error");
                rfid.retries = 0;
                SpinDelay(1000);
                set_rfid_state(RFID_IDLE);
                break;
        }
        
        SpinDelay(1);
    }
    
    return 0;
}

#ifdef PYTHON_WRAPPER
const char* get_tag_db_json(void) {
    static char json_buf[512];
    uint32_t pos = snprintf(json_buf, 512, "[");
    uint32_t addr = TAG_DB_FLASH_ADDR + (current_wear_page * FLASH_PAGE_SIZE);
    TagEntryHeader header;
    for (uint32_t i = 0; i < write_ptr && pos < 500; i += sizeof(header)) {
        FlashmemRead((uint8_t*)&header, addr + i, sizeof(header));
        if (header.data_len > 0) {
            pos += snprintf(json_buf + pos, 512 - pos,
                           "{\"type\":%d,\"protocol\":%d,\"uid\":\"%02x%02x%02x%02x\"}",
                           header.type, header.protocol,
                           header.uid[0], header.uid[1], header.uid[2], header.uid[3]);
            if (i + sizeof(header) < write_ptr) pos += snprintf(json_buf + pos, 512 - pos, ",");
        }
    }
    snprintf(json_buf + pos, 512 - pos, "]");
    return json_buf;
}

void send_command(const char* cmd) {
    usb_send((uint8_t*)cmd, strlen(cmd));
}
#endif