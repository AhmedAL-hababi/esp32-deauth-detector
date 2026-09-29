idf_component_register(
    SRCS "blink_example_main.c"
    INCLUDE_DIRS "."
    REQUIRES present_cipher esp_wifi nvs_flash esp_event driver mbedtls hd44780 esp_idf_lib_helpers
)