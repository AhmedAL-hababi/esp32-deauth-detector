#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "driver/gpio.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "present_cipher.h"
#include "hd44780.h"

/* ==================== Configuration ==================== */
#define LED_GPIO                    GPIO_NUM_2
#define WIFI_SSID                   "MohWifi"
#define WIFI_PASS                   "Mohalicyber774350060"

/* LCD Configuration */
#define LCD_RS_GPIO                 GPIO_NUM_22
#define LCD_E_GPIO                  GPIO_NUM_23
#define LCD_D4_GPIO                 GPIO_NUM_18
#define LCD_D5_GPIO                 GPIO_NUM_19
#define LCD_D6_GPIO                 GPIO_NUM_21
#define LCD_D7_GPIO                 GPIO_NUM_5
#define LCD_COLS                    16
#define LCD_ROWS                    2

/* Email Configuration */
#define SMTP_SERVER                 "smtp.gmail.com"
#define SMTP_PORT                   465
#define SMTP_USERNAME               "<Put Email_1>"
#define SMTP_PASSWORD               "Put AppPassword"
#define EMAIL_TO_1                  "Put Email_1"
#define EMAIL_TO_2                  "Put Email_2"
#define ALERT_TAG                   "[PRESENT-ALERT]"

/* Router BSSID (used as default attacker MAC) */
#define ROUTER_BSSID_0              0x7C
#define ROUTER_BSSID_1              0x45
#define ROUTER_BSSID_2              0xD0
#define ROUTER_BSSID_3              0x4D
#define ROUTER_BSSID_4              0xC4
#define ROUTER_BSSID_5              0x53

/* Timing */
#define ATTACK_SETTLE_DELAY_MS      10000
#define WIFI_CONNECT_TIMEOUT_MS     30000

/* ==================== Global Variables ==================== */
static const char *TAG = "DEAUTH_DETECTOR";
static hd44780_t s_lcd;

static const uint8_t SECRET_KEY[PRESENT_KEY_SIZE_BYTES] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x12, 0x34
};

typedef struct {
    uint32_t attack_count;
    uint32_t timestamp;
    uint8_t  attacker_mac[6];
    uint16_t reason_code;
} attack_info_t;

static volatile attack_info_t s_last_attack = {0};
static volatile uint32_t s_pending_report = 0;
static EventGroupHandle_t s_wifi_event_group;
static volatile bool s_sniffer_active = false;

#define WIFI_CONNECTED_BIT BIT0

/* ==================== Function Prototypes ==================== */
static void encrypt_and_send_email(void);
static void start_sniffer(void);
static void stop_sniffer(void);
static int send_alert_email(const char *encrypted_hex);
static void lcd_display_status(const char *line1, const char *line2);

/* ==================== LCD Helper ==================== */
static void lcd_display_status(const char *line1, const char *line2) {
    hd44780_clear(&s_lcd);
    hd44780_gotoxy(&s_lcd, 0, 0);
    hd44780_puts(&s_lcd, line1);
    hd44780_gotoxy(&s_lcd, 0, 1);
    hd44780_puts(&s_lcd, line2);
}

static void lcd_display_attack(void) {
    char line2[18];
    snprintf(line2, sizeof(line2), "%02X:%02X:%02X:%02X:%02X:%02X",
             ROUTER_BSSID_0, ROUTER_BSSID_1, ROUTER_BSSID_2,
             ROUTER_BSSID_3, ROUTER_BSSID_4, ROUTER_BSSID_5);
    lcd_display_status("DEAUTH ATTACK!", line2);
}

/* ==================== Wi-Fi Event Handler ==================== */
static void wifi_event_handler(void* arg, esp_event_base_t event_base,int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        /* Do not auto-connect */
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *disc = (wifi_event_sta_disconnected_t *)event_data;

        ESP_LOGW(TAG, "");
        ESP_LOGW(TAG, "==================================================");
        ESP_LOGW(TAG, "  [!] Wi-Fi DISCONNECTED!");
        ESP_LOGW(TAG, "  Reason Code : %d", disc->reason);
        ESP_LOGE(TAG, "  [!!!] POSSIBLE DEAUTH ATTACK DETECTED!");

        s_last_attack.attack_count++;
        s_last_attack.timestamp = (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS / 1000);
        s_last_attack.reason_code = disc->reason;
        
        /* Use Router BSSID as attacker MAC */
        s_last_attack.attacker_mac[0] = ROUTER_BSSID_0;
        s_last_attack.attacker_mac[1] = ROUTER_BSSID_1;
        s_last_attack.attacker_mac[2] = ROUTER_BSSID_2;
        s_last_attack.attacker_mac[3] = ROUTER_BSSID_3;
        s_last_attack.attacker_mac[4] = ROUTER_BSSID_4;
        s_last_attack.attacker_mac[5] = ROUTER_BSSID_5;
        
        s_pending_report = 1;

        /* Display on LCD */
        lcd_display_attack();

        ESP_LOGW(TAG, "==================================================");
        ESP_LOGW(TAG, "");

        xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "");
        ESP_LOGI(TAG, "==================================================");
        ESP_LOGI(TAG, "  [OK] Wi-Fi RECONNECTED!");
        ESP_LOGI(TAG, "  IP Address : " IPSTR, IP2STR(&event->ip_info.ip));
        ESP_LOGI(TAG, "==================================================");
        ESP_LOGI(TAG, "");
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

/* ==================== SMTP Email Sender ==================== */
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/base64.h"

static int smtp_send_cmd(mbedtls_ssl_context *ssl, const char *cmd) {
    return mbedtls_ssl_write(ssl, (const unsigned char *)cmd, strlen(cmd));
}

static int smtp_read_resp(mbedtls_ssl_context *ssl) {
    char buf[512];
    int ret = mbedtls_ssl_read(ssl, (unsigned char *)buf, sizeof(buf) - 1);
    if (ret > 0) {
        buf[ret] = '\0';
    }
    return ret;
}

static int send_alert_email(const char *encrypted_hex) {
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    char buf[1024];
    int ret;

    ESP_LOGI(TAG, "[EMAIL] Opening TLS connection to %s:%d...", SMTP_SERVER, SMTP_PORT);

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char *pers = "smtp";
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers, strlen(pers))) != 0) {
        ESP_LOGE(TAG, "[EMAIL] RNG seed failed: -0x%04X", -ret);
        goto cleanup;
    }

    if ((ret = mbedtls_net_connect(&server_fd, SMTP_SERVER, "465",
                                   MBEDTLS_NET_PROTO_TCP)) != 0) {
        ESP_LOGE(TAG, "[EMAIL] Connection failed: -0x%04X", -ret);
        goto cleanup;
    }

    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                 MBEDTLS_SSL_TRANSPORT_STREAM,
                                 MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        ESP_LOGE(TAG, "[EMAIL] SSL setup failed: -0x%04X", -ret);
        goto cleanup;
    }
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGE(TAG, "[EMAIL] Handshake failed: -0x%04X", -ret);
            goto cleanup;
        }
    }
    ESP_LOGI(TAG, "[EMAIL] TLS connection established.");

    smtp_read_resp(&ssl);
    smtp_send_cmd(&ssl, "EHLO esp32\r\n");
    smtp_read_resp(&ssl);

    smtp_send_cmd(&ssl, "AUTH LOGIN\r\n");
    smtp_read_resp(&ssl);

    size_t enc_len;
    mbedtls_base64_encode((unsigned char *)buf, sizeof(buf), &enc_len,
                          (const unsigned char *)SMTP_USERNAME, strlen(SMTP_USERNAME));
    buf[enc_len] = '\0';
    snprintf(buf + enc_len, sizeof(buf) - enc_len, "\r\n");
    smtp_send_cmd(&ssl, buf);
    smtp_read_resp(&ssl);

    mbedtls_base64_encode((unsigned char *)buf, sizeof(buf), &enc_len,
                          (const unsigned char *)SMTP_PASSWORD, strlen(SMTP_PASSWORD));
    buf[enc_len] = '\0';
    snprintf(buf + enc_len, sizeof(buf) - enc_len, "\r\n");
    smtp_send_cmd(&ssl, buf);
    smtp_read_resp(&ssl);

    snprintf(buf, sizeof(buf), "MAIL FROM:<%s>\r\n", SMTP_USERNAME);
    smtp_send_cmd(&ssl, buf);
    smtp_read_resp(&ssl);

    snprintf(buf, sizeof(buf), "RCPT TO:<%s>\r\n", EMAIL_TO_1);
    smtp_send_cmd(&ssl, buf);
    smtp_read_resp(&ssl);

    snprintf(buf, sizeof(buf), "RCPT TO:<%s>\r\n", EMAIL_TO_2);
    smtp_send_cmd(&ssl, buf);
    smtp_read_resp(&ssl);

    smtp_send_cmd(&ssl, "DATA\r\n");
    smtp_read_resp(&ssl);

    snprintf(buf, sizeof(buf),
             "From: %s\r\n"
             "To: %s, %s\r\n"
             "Subject: %s Deauth Attack Detected\r\n"
             "\r\n"
             "%s\r\n"
             "Encrypted Data: %s\r\n"
             ".\r\n",
             SMTP_USERNAME, EMAIL_TO_1, EMAIL_TO_2,
             ALERT_TAG, ALERT_TAG, encrypted_hex);
    smtp_send_cmd(&ssl, buf);
    smtp_read_resp(&ssl);

    smtp_send_cmd(&ssl, "QUIT\r\n");
    smtp_read_resp(&ssl);

    ESP_LOGI(TAG, "[EMAIL] Sent successfully to %s and %s", EMAIL_TO_1, EMAIL_TO_2);
    ret = 0;

cleanup:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

/* ==================== Encrypt & Send ==================== */
static void encrypt_and_send_email(void) {
    uint8_t plaintext[PRESENT_BLOCK_SIZE_BYTES * 2] = {0};
    uint8_t ciphertext[PRESENT_BLOCK_SIZE_BYTES * 2] = {0};

    uint32_t count = s_last_attack.attack_count;
    uint32_t ts = s_last_attack.timestamp;
    for (int i = 0; i < 4; i++) {
        plaintext[i] = (count >> (24 - i * 8)) & 0xFF;
        plaintext[4 + i] = (ts >> (24 - i * 8)) & 0xFF;
    }

    memcpy(&plaintext[8], (const void *)s_last_attack.attacker_mac, 6);
    plaintext[14] = (s_last_attack.reason_code >> 8) & 0xFF;
    plaintext[15] = s_last_attack.reason_code & 0xFF;

    present_encrypt_block(&plaintext[0], &ciphertext[0]);
    present_encrypt_block(&plaintext[8], &ciphertext[8]);

    char hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(hex + (i * 2), "%02X", ciphertext[i]);
    }
    hex[32] = '\0';

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "==================================================");
    ESP_LOGI(TAG, "  [ENCRYPT] Encrypted Payload (HEX):");
    ESP_LOGI(TAG, "  %s", hex);
    ESP_LOGI(TAG, "==================================================");
    ESP_LOGI(TAG, "");

    send_alert_email(hex);
}

/* ==================== Sniffer Callback ==================== */
static void wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *payload = pkt->payload;

    if (payload[0] == 0x00 && payload[1] == 0xC0) {
        memcpy((void *)s_last_attack.attacker_mac, &payload[10], 6);
        s_last_attack.reason_code = (payload[24] | (payload[25] << 8));
        s_last_attack.timestamp = (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS / 1000);
        s_last_attack.attack_count++;
        s_pending_report = 1;

        ESP_LOGE(TAG, "");
        ESP_LOGE(TAG, "==================================================");
        ESP_LOGE(TAG, "  [!!!] DEAUTH ATTACK DETECTED VIA SNIFFER!");
        ESP_LOGE(TAG, "--------------------------------------------------");
        ESP_LOGE(TAG, "  Total Attacks : %lu", s_last_attack.attack_count);
        ESP_LOGE(TAG, "  Attacker MAC  : %02X:%02X:%02X:%02X:%02X:%02X",
                 s_last_attack.attacker_mac[0], s_last_attack.attacker_mac[1],
                 s_last_attack.attacker_mac[2], s_last_attack.attacker_mac[3],
                 s_last_attack.attacker_mac[4], s_last_attack.attacker_mac[5]);
        ESP_LOGE(TAG, "  Reason Code   : %u", s_last_attack.reason_code);
        ESP_LOGE(TAG, "==================================================");
        ESP_LOGE(TAG, "");

        /* Display on LCD */
        char line2[18];
        snprintf(line2, sizeof(line2), "%02X:%02X:%02X:%02X:%02X:%02X",
                 s_last_attack.attacker_mac[0], s_last_attack.attacker_mac[1],
                 s_last_attack.attacker_mac[2], s_last_attack.attacker_mac[3],
                 s_last_attack.attacker_mac[4], s_last_attack.attacker_mac[5]);
        lcd_display_status("DEAUTH ATTACK!", line2);

        gpio_set_level(LED_GPIO, 1);
        vTaskDelay(pdMS_TO_TICKS(100));
        gpio_set_level(LED_GPIO, 0);
    }
}

/* ==================== Sniffer Control ==================== */
static void start_sniffer(void) {
    if (s_sniffer_active) return;
    ESP_LOGI(TAG, "[SNIFFER] Starting Sniffer on channel 6...");
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_cb);
    s_sniffer_active = true;
}

static void stop_sniffer(void) {
    if (!s_sniffer_active) return;
    ESP_LOGI(TAG, "[SNIFFER] Stopping Sniffer...");
    esp_wifi_set_promiscuous(false);
    s_sniffer_active = false;
}

/* ==================== Main Application ==================== */
void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    gpio_reset_pin(LED_GPIO);
    gpio_set_direction(LED_GPIO, GPIO_MODE_OUTPUT);

    if (present_init(SECRET_KEY) != 0) {
        ESP_LOGE(TAG, "PRESENT init failed.");
        return;
    }

    /* ===== Initialize LCD ===== */
    hd44780_t lcd_config = {
        .write_cb = NULL,
        .font = HD44780_FONT_5X8,
        .lines = LCD_ROWS,
        .pins = {
            .rs = LCD_RS_GPIO,
            .e  = LCD_E_GPIO,
            .d4 = LCD_D4_GPIO,
            .d5 = LCD_D5_GPIO,
            .d6 = LCD_D6_GPIO,
            .d7 = LCD_D7_GPIO,
            .bl = HD44780_NOT_USED,
        },
    };
    ESP_ERROR_CHECK(hd44780_init(&lcd_config));
    s_lcd = lcd_config;
    hd44780_clear(&s_lcd);
    hd44780_gotoxy(&s_lcd, 0, 0);
    hd44780_puts(&s_lcd, "System Ready");
    hd44780_gotoxy(&s_lcd, 0, 1);
    hd44780_puts(&s_lcd, "Monitoring...");

    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler, NULL, NULL));

    wifi_config_t wifi_config = {
        .sta = { .ssid = WIFI_SSID, .password = WIFI_PASS },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_ERROR_CHECK(esp_wifi_set_channel(6, WIFI_SECOND_CHAN_NONE));

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "==================================================");
    ESP_LOGI(TAG, "       DEAUTH DETECTOR - SYSTEM READY");
    ESP_LOGI(TAG, "--------------------------------------------------");
    ESP_LOGI(TAG, "  SSID       : %s", WIFI_SSID);
    ESP_LOGI(TAG, "  Channel    : 6");
    ESP_LOGI(TAG, "  Alert Email: %s", EMAIL_TO_1);
    ESP_LOGI(TAG, "  Alert Email: %s", EMAIL_TO_2);
    ESP_LOGI(TAG, "  Status     : Connecting to Wi-Fi...");
    ESP_LOGI(TAG, "==================================================");
    ESP_LOGI(TAG, "");

    /* Connect to Wi-Fi FIRST */
    ESP_LOGI(TAG, "Connecting to Wi-Fi...");
    lcd_display_status("Connecting...", "Wi-Fi");
    esp_wifi_connect();
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT,
                        pdFALSE, pdTRUE, portMAX_DELAY);
    ESP_LOGI(TAG, "Wi-Fi Connected. Starting Sniffer...");

    lcd_display_status("Wi-Fi Connected", "Monitoring...");

    /* THEN start sniffer */
    start_sniffer();

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(5000));

        if (s_pending_report) {
            ESP_LOGW(TAG, "");
            ESP_LOGW(TAG, "==================================================");
            ESP_LOGW(TAG, "  [PHASE 1] Attack detected. Waiting 10 seconds...");
            ESP_LOGW(TAG, "==================================================");
            ESP_LOGW(TAG, "");

            lcd_display_status("Attack Detected", "Sending report...");

            vTaskDelay(pdMS_TO_TICKS(ATTACK_SETTLE_DELAY_MS));

            ESP_LOGW(TAG, "");
            ESP_LOGW(TAG, "==================================================");
            ESP_LOGW(TAG, "  [PHASE 2] Connecting to Wi-Fi...");
            ESP_LOGW(TAG, "==================================================");
            ESP_LOGW(TAG, "");

            stop_sniffer();

            xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
            esp_wifi_connect();

            EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT,
                                                    pdFALSE, pdTRUE,
                                                    pdMS_TO_TICKS(WIFI_CONNECT_TIMEOUT_MS));
            if (!(bits & WIFI_CONNECTED_BIT)) {
                ESP_LOGE(TAG, "");
                ESP_LOGE(TAG, "==================================================");
                ESP_LOGE(TAG, "  [X] Wi-Fi Connection FAILED. Retrying...");
                ESP_LOGE(TAG, "==================================================");
                ESP_LOGE(TAG, "");
                lcd_display_status("Wi-Fi Failed", "Retrying...");
                esp_wifi_set_channel(6, WIFI_SECOND_CHAN_NONE);
                start_sniffer();
                continue;
            }

            ESP_LOGI(TAG, "");
            ESP_LOGI(TAG, "==================================================");
            ESP_LOGI(TAG, "  [PHASE 3] Sending encrypted email...");
            ESP_LOGI(TAG, "==================================================");
            ESP_LOGI(TAG, "");

            encrypt_and_send_email();
            s_pending_report = 0;

            ESP_LOGI(TAG, "");
            ESP_LOGI(TAG, "==================================================");
            ESP_LOGI(TAG, "  [OK] Report sent! Resuming sniffer...");
            ESP_LOGI(TAG, "==================================================");
            ESP_LOGI(TAG, "");

            lcd_display_status("Report Sent!", "Monitoring...");

            esp_wifi_disconnect();
            vTaskDelay(pdMS_TO_TICKS(1000));
            esp_wifi_set_channel(6, WIFI_SECOND_CHAN_NONE);
            start_sniffer();
        }
    }
}



