/*
    file: SSLInterface.c
    description: mbedtls callback functions
    author: peter
    company: wiznet
    data: 2015.11.26
*/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
//#include "stm32l5xx.h"

#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl_cache.h"
#include "psa/crypto.h"
#include "port_common.h"

#include "SSLInterface.h"
#include "SSL_Random.h"
#include "socket.h"
#include "ConfigData.h"
#include "timerHandler.h"
#include "deviceHandler.h"
#include "storageHandler.h"
#include "common.h"
#include "util.h"

//unsigned char tempBuf[DEBUG_BUFFER_SIZE] = {0,};
static int wiz_tls_init_state;

static mbedtls_ssl_cache_context https_session_cache;
static uint8_t https_session_cache_initialized = 0;
/*
    Self-signed development certificate (RSA-2048), demo use only.
    Browsers will show a security warning — this is expected for a
    self-signed cert. Regenerate your own before any real deployment:
    see cert_work/README.md.
*/
static const char HTTPS_SERVER_CERT[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDnDCCAoSgAwIBAgIUET9Xo4yqeaQnwxzk9RsBT/aP25IwDQYJKoZIhvcNAQEL\r\n"
    "BQAwTzELMAkGA1UEBhMCS1IxFDASBgNVBAoMC1dJWm5ldCBEZW1vMRMwEQYDVQQL\r\n"
    "DApIVFRQUyBUZXN0MRUwEwYDVQQDDAxXNTVSUDIwLURlbW8wHhcNMjYwNjE2MDYx\r\n"
    "MjEyWhcNMzYwNjEzMDYxMjEyWjBPMQswCQYDVQQGEwJLUjEUMBIGA1UECgwLV0la\r\n"
    "bmV0IERlbW8xEzARBgNVBAsMCkhUVFBTIFRlc3QxFTATBgNVBAMMDFc1NVJQMjAt\r\n"
    "RGVtbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIXw7B+pv2KDBneX\r\n"
    "OzJJQlGlmMG4uTluypDNWSYoEj2dBUyau4t7trvnscJfliHC5/5/gBgHnfXk9YzO\r\n"
    "782K9sAIEsvTym1PHJCGUgyXUHSiMGv2MluQydfCgZHa4f95baoATZrnzqpoSFRv\r\n"
    "akuQ5PQmt3xZnUxkcVYcs8mVU+EFXdRPVbyx0YF5Ym7Dv2y/T11eSheB5t/314u3\r\n"
    "eYXtH26LXwS6tKg2d8ADaG2ulwCclhi/w9dY2B5EN8eR2uUd+3eWS+cHdH37lLyU\r\n"
    "0b3OuNSAZLypkJWIi1xiyV+TeJmhvN28zGyvOVKh47JoFs0GM74qG5tKQrC/FRph\r\n"
    "+EpnSzcCAwEAAaNwMG4wHQYDVR0OBBYEFNtlzG62aXqPpaz6J5TpzRciRqFmMB8G\r\n"
    "A1UdIwQYMBaAFNtlzG62aXqPpaz6J5TpzRciRqFmMAwGA1UdEwQFMAMBAf8wHgYD\r\n"
    "VR0RBBcwFYcEwKgLdoINdzU1cnAyMC5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEA\r\n"
    "O1/oN20tZmWMPDKrNqXFTIMoE4okRWMRQNE9KmYAU1bjeQE1h/m/sjmIoEWVDDyJ\r\n"
    "7jz6dqYq8A2vC5LNYlSX8rdnS1+9F7Bbuud2gJ4ZNKkcQwI+E3x5HXMDcuvyvuGX\r\n"
    "hGKDNgKHd9GxwIedq8E0ekiBEi8b8/Qzf68ZxnsFrnF0qMEV76crpWbBuKq0t6/C\r\n"
    "KEWPw+VDpbLRSoIy+8HVMq+L1RsIDp79UB10b9+0Vts17js1lhqGIwCiqt6vnWN2\r\n"
    "l7CiDQ4tFPWvElpYwMq40nKPP5oyiuXVZgbU3Ng0sNk8vszBMtDtjf6XZlVfusFH\r\n"
    "W9pirNjEFyOV1UCAVbAHMw==\r\n"
    "-----END CERTIFICATE-----\r\n";
static const char HTTPS_SERVER_KEY[] =
    "-----BEGIN PRIVATE KEY-----\r\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCF8Owfqb9igwZ3\r\n"
    "lzsySUJRpZjBuLk5bsqQzVkmKBI9nQVMmruLe7a757HCX5Yhwuf+f4AYB5315PWM\r\n"
    "zu/NivbACBLL08ptTxyQhlIMl1B0ojBr9jJbkMnXwoGR2uH/eW2qAE2a586qaEhU\r\n"
    "b2pLkOT0Jrd8WZ1MZHFWHLPJlVPhBV3UT1W8sdGBeWJuw79sv09dXkoXgebf99eL\r\n"
    "t3mF7R9ui18EurSoNnfAA2htrpcAnJYYv8PXWNgeRDfHkdrlHft3lkvnB3R9+5S8\r\n"
    "lNG9zrjUgGS8qZCViItcYslfk3iZobzdvMxsrzlSoeOyaBbNBjO+KhubSkKwvxUa\r\n"
    "YfhKZ0s3AgMBAAECggEABiQHCZ1yDOM+OgSum74YO8h5l6CqzwEPIEmvk0oMmAog\r\n"
    "ZP+hptjN9CNS4BaIzJ4rC7h4Bb1wzZhyB4wfPtiLXxroy2nukG49l83R1+WCD9yR\r\n"
    "KZxB5qRdglrpCoygz3SXYOFn9pQ3ZwmmM0cXiGk71xzgutD3jLn8uszjE0H04k6Y\r\n"
    "V4+HJsY8Au6QkB7ORhH2cICwijHj/2z5vWtFVXkPT8/qDkFf0zblgpVIktmnFvDj\r\n"
    "UHyU6ZbHkctDv0SnAKx+noWQp/iR02QXs2rYio68G57pmN7n8s07wD1IYtt48jdo\r\n"
    "GW5NZhfWhmxPMT0tRkZfP+bR7tXxMCU9eW4qBUTazQKBgQC67M/j0mslUmD1o9KA\r\n"
    "4RKD5Nfly3GogQYwDF9eOLX92FBXYvJQg+E79z03TfKMnSGIuJWxJHd5swGRYl90\r\n"
    "GhNrRLYnJ5QjmRRNKgWYXPv1VZZ0wy5AouOGm9tkLJmsOtpCzwwWrNXjQ0M5RWE5\r\n"
    "B3cdounwlGSGPnnAD5GDKOvCxQKBgQC3b86Sr5T8IzDu2WUrge+Pv112BdU7NbDC\r\n"
    "XoW9rMQEnGmrrdUj5He9P+jWV7LeSGN1yd8ou66tv1me1XuUJbVB+e7f1DbbyDEA\r\n"
    "X6dYg/IEvGKLvcYALnogl0a9tJdoSPY/9S5Jf2eAxb1Ix+fEQHxv89IewDDZ8vSc\r\n"
    "oitDHG4FywKBgFgEKAODUfZZ6tPfVsBeuoQmXk6S1CrezhYTzVglZfRoRbRQH/8v\r\n"
    "if/ddBK1fk8dseuZ1sp5fFRuqH9XjdCycpBg41Bef4+fhgKrlcTfi7hCm7zRJtdC\r\n"
    "m9YHT2/E3HtPnvQ0X+HRckk3o9C0zYm37SukSXmBti/L/TIlYoQa4aBtAoGBALPF\r\n"
    "JBpHbufnCRabAPYxgfhLX6nBr6Y2SQNDpSgsv3GRZFH2q1JgniRfFK2zBr2nDaoq\r\n"
    "68O8o0TtqUPrDhAzID8HVN4Q2K5ts/AcziEGNlID2UP/+KLG6bM07gQOju+JyaMG\r\n"
    "gpVPAb2GjKleGDoRxKHmvn6adYWy/5zdpS5BF2YfAoGAOh3/QIDWmJsS3jlUpXjI\r\n"
    "LndhLE8SKQ31Vi9xAVDEXXR0/WQ8kFm8JGH2PNeNkTTDaNZwwglelKFSlk0yquRq\r\n"
    "sJuKY/zqXFD61/n5D9vz+RuEz2JupUGU06Al2wq8HAwGZXORIOn4HAm40JVPxcdm\r\n"
    "X2cF8lDgDtWb7buJ6AEI6yc=\r\n"
    "-----END PRIVATE KEY-----\r\n";

int WIZnetRecvTimeOut(void *ctx, unsigned char *buf, size_t len, uint32_t timeout) {
    uint8_t sock = (uint8_t)(uintptr_t)ctx;
    uint32_t start_ms = millis();
    int ret;
    uint16_t recv_size;

    do {
        recv_size = getSn_RX_RSR(sock);
        if (recv_size) {
            ret = recv(sock, (uint8_t *)buf, recv_size > len ? len : recv_size);
            if (ret < 0) {
                return MBEDTLS_ERR_SSL_WANT_READ;
            }
            return ret;
        }
        vTaskDelay(10);
    } while ((millis() - start_ms) < timeout);

    return MBEDTLS_ERR_SSL_TIMEOUT;
}

/*Shell for mbedtls recv function*/
int WIZnetRecv(void *ctx, unsigned char *buf, unsigned int len) {
    uint8_t sock = (uint8_t)(uintptr_t)ctx;
    int ret;
    uint16_t recv_size;

    recv_size = getSn_RX_RSR(sock);
    if (recv_size > 0) {
        ret = recv(sock, (uint8_t *)buf, recv_size > len ? len : recv_size);
        if (ret < 0) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        return ret;
    }

    if (getSn_SR(sock) == SOCK_CLOSE_WAIT || getSn_SR(sock) == SOCK_CLOSED) {
        return 0;
    }

    return MBEDTLS_ERR_SSL_WANT_READ;
}

/*Shell for mbedtls recv non-block function*/
int WIZnetRecvNB(void *ctx, unsigned char *buf, unsigned int len) {
    uint8_t sock = (uint8_t)(uintptr_t)ctx;
    int ret;
    uint16_t recv_size;

    recv_size = getSn_RX_RSR(sock);
    if (recv_size > 0) {
        ret = recv(sock, (uint8_t *)buf, recv_size > len ? len : recv_size);
        if (ret < 0) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        return ret;
    }

    if (getSn_SR(sock) == SOCK_CLOSE_WAIT || getSn_SR(sock) == SOCK_CLOSED) {
        return 0;
    }

    return MBEDTLS_ERR_SSL_WANT_READ;
}


/*Shell for mbedtls send function*/
int WIZnetSend(void *ctx, const unsigned char *buf, unsigned int len) {
    uint8_t sock = (uint8_t)(uintptr_t)ctx;
    int ret = send(sock, (uint8_t *)buf, (uint16_t)len);

    /*  SOCK_BUSY(0): 이전 SEND가 아직 완료되지 않음 (TLS 레코드가 W5500
        2KB TX 버퍼보다 클 때 부분 전송 직후 발생). 0을 그대로 반환하면
        mbedTLS가 치명 오류로 처리하므로 WANT_WRITE로 바꿔 재시도시킨다. */
    if (ret == SOCK_BUSY) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    if (ret < 0) {
        if (getSn_SR(sock) == SOCK_CLOSE_WAIT || getSn_SR(sock) == SOCK_CLOSED) {
            return MBEDTLS_ERR_SSL_CONN_EOF;
        }
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }

    return ret;
}

/*  Shell for mbedtls debug function.
    DEBUG_LEBEL can be changed from 0 to 3*/
#ifdef MBEDTLS_DEBUG_C
void WIZnetDebugCB(void *ctx, int level, const char *file, int line, const char *str) {
    if (level <= DEBUG_LEVEL) {
        printf("%s\r\n", str);
    }
}
#endif


/*  SSL context initialization
 * */
int wiz_tls_init(wiz_tls_context* tlsContext, int* socket_fd) {
    struct __ssl_option *ssl_option = (struct __ssl_option *) & (get_DevConfig_pointer()->ssl_option);
    int ret = 1;
    const char *pers = "ssl_client1";
    uint8_t *rootca_addr = NULL;
    uint8_t *clica_addr = NULL;
    uint8_t *pkey_addr = NULL;
#if defined (MBEDTLS_ERROR_C)
    char error_buf[100];
#endif

#if defined (MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    /*
        Initialize session data
    */
    /* PSA Crypto must be initialized before TLS 1.3 handshake */
    psa_status_t psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        PRT_SSL(" failed\r\n  ! psa_crypto_init returned %d\r\n", (int)psa_status);
        return -1;
    }
#if defined (MBEDTLS_ENTROPY_C)
    tlsContext->entropy = pvPortMalloc(sizeof(mbedtls_entropy_context));
#endif
    tlsContext->ctr_drbg = pvPortMalloc(sizeof(mbedtls_ctr_drbg_context));
    tlsContext->ssl = pvPortMalloc(sizeof(mbedtls_ssl_context));
    tlsContext->conf = pvPortMalloc(sizeof(mbedtls_ssl_config));
    tlsContext->cacert = pvPortMalloc(sizeof(mbedtls_x509_crt));
    tlsContext->clicert = pvPortMalloc(sizeof(mbedtls_x509_crt));
    tlsContext->pkey = pvPortMalloc(sizeof(mbedtls_pk_context));

#if defined (MBEDTLS_ENTROPY_C)
    mbedtls_entropy_init(tlsContext->entropy);
#endif

    mbedtls_ctr_drbg_init(tlsContext->ctr_drbg);
    mbedtls_ssl_init(tlsContext->ssl);
    mbedtls_ssl_config_init(tlsContext->conf);
    mbedtls_x509_crt_init(tlsContext->cacert);
    mbedtls_x509_crt_init(tlsContext->clicert);
    mbedtls_pk_init(tlsContext->pkey);
    const int *ciphersuite_list = mbedtls_ssl_list_ciphersuites();
    while (*ciphersuite_list != 0) {
        const char *name = mbedtls_ssl_get_ciphersuite_name(*ciphersuite_list);
        if (name != NULL) {
            PRT_SSL("%s\r\n", name);
        }
        ciphersuite_list++;
    }
    /*
        Initialize certificates
    */
#if defined (MBEDTLS_ENTROPY_C)
    if ((ret = mbedtls_ctr_drbg_seed(tlsContext->ctr_drbg, mbedtls_entropy_func, tlsContext->entropy,    \
                                     (const unsigned char *) pers, strlen(pers))) != 0) {
        PRT_SSL(" failed\r\n  ! mbedtls_ctr_drbg_seed returned -0x%x\r\n", -ret);
        return -1;
    }
#endif

#if defined (MBEDTLS_DEBUG_C)
    mbedtls_ssl_conf_dbg(tlsContext->conf, WIZnetDebugCB, stdout);
#endif

    /*
        Parse certificate
    */
    if (ssl_option->root_ca_option != MBEDTLS_SSL_VERIFY_NONE) {
        PRT_SSL(" Loading the CA root certificate len = %d\r\n", ssl_option->rootca_len);
        rootca_addr = (uint8_t *)(FLASH_ROOTCA_ADDR + XIP_BASE);
        ret = mbedtls_x509_crt_parse(tlsContext->cacert, (const char *)rootca_addr, ssl_option->rootca_len + 1);
        if (ret < 0) {
            PRT_SSL(" failed\r\n  !  mbedtls_x509_crt_parse returned -0x%x while parsing root cert\r\n", -ret);
            return -1;
        }
        PRT_SSL("ok! mbedtls_x509_crt_parse returned -0x%x while parsing root cert\r\n", -ret);

        uint8_t ip_temp[4];
        struct __network_connection *network_connection = (struct __network_connection *) & (get_DevConfig_pointer()->network_connection);
        if (!is_ipaddr(network_connection->dns_domain_name, ip_temp)) {
            if ((ret = mbedtls_ssl_set_hostname(tlsContext->ssl, network_connection->dns_domain_name)) != 0) {
                PRT_SSL(" failed mbedtls_ssl_set_hostname returned %d\r\n", ret);
                return -1;
            }
        } else {
            if ((ret = mbedtls_ssl_set_hostname(tlsContext->ssl, NULL)) != 0) {
                PRT_SSL(" failed mbedtls_ssl_set_hostname returned %d\r\n", ret);
                return -1;
            }
        }
        PRT_SSL("ok! mbedtls_ssl_set_hostname returned %d\r\n", ret);
    }

    if (ssl_option->client_cert_enable == ENABLE) {
        clica_addr = (uint8_t *)(FLASH_CLICA_ADDR + XIP_BASE);
        pkey_addr = (uint8_t *)(FLASH_PRIKEY_ADDR + XIP_BASE);

        ret = mbedtls_x509_crt_parse((tlsContext->clicert), (const char *)clica_addr, ssl_option->clica_len + 1);
        if (ret != 0) {
            PRT_SSL(" failed\r\n  !  mbedtls_x509_crt_parse returned -0x%x while parsing device cert\r\n", -ret);
            return -1;
        }
        PRT_SSL("ok! mbedtls_x509_crt_parse returned -0x%x while parsing device cert\r\n", -ret);

        ret = mbedtls_pk_parse_key(tlsContext->pkey, (const char *)pkey_addr, ssl_option->pkey_len + 1, NULL, 0, mbedtls_ctr_drbg_random, tlsContext->ctr_drbg);
        if (ret != 0) {
            PRT_SSL(" failed\r\n  !  mbedtls_pk_parse_key returned -0x%x while parsing private key\r\n", -ret);
            return -1;
        }
        PRT_SSL("ok! mbedtls_pk_parse_key returned -0x%x while parsing private key\r\n", -ret);
    }

    if ((ret = mbedtls_ssl_config_defaults(tlsContext->conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        PRT_SSL(" failed mbedtls_ssl_config_defaults returned %d\r\n", ret);
        return -1;
    }

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    mbedtls_ssl_conf_tls13_key_exchange_modes(tlsContext->conf,
            MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL);
#endif

    PRT_SSL("ssl_option->root_ca_option = %d\r\n", ssl_option->root_ca_option);
    PRT_SSL("socket_fd = %d\r\n", socket_fd);
    mbedtls_ssl_conf_authmode(tlsContext->conf, ssl_option->root_ca_option);
    mbedtls_ssl_conf_ca_chain(tlsContext->conf, tlsContext->cacert, NULL);
    mbedtls_ssl_conf_rng(tlsContext->conf, mbedtls_ctr_drbg_random, tlsContext->ctr_drbg);

    if (ssl_option->client_cert_enable == ENABLE) {
        if ((ret = mbedtls_ssl_conf_own_cert(tlsContext->conf, tlsContext->clicert, tlsContext->pkey)) != 0) {
            PRT_SSL("failed! mbedtls_ssl_conf_own_cert returned %d\r\n", ret);
            return -1;
        }
        PRT_SSL("ok! mbedtls_ssl_conf_own_cert returned %d\r\n", ret);
    }

    mbedtls_ssl_conf_endpoint(tlsContext->conf, MBEDTLS_SSL_IS_CLIENT);
    if (ssl_option->recv_timeout == 0) {
        ssl_option->recv_timeout = 2000;
    }
    mbedtls_ssl_conf_read_timeout(tlsContext->conf, ssl_option->recv_timeout);

    if ((ret = mbedtls_ssl_setup(tlsContext->ssl, tlsContext->conf)) != 0) {
        PRT_SSL(" failed mbedtls_ssl_setup returned -0x%x\r\n", -ret);
        return -1;
    }
    tlsContext->socket_fd = (uint8_t)(*socket_fd);
    mbedtls_ssl_set_bio(tlsContext->ssl,
                        (void *)(uintptr_t)tlsContext->socket_fd,
                        SSLSendCB, SSLRecvCB, SSLRecvTimeOutCB);

    PRT_SSL("return 1\r\n");
    return 1;
}

int wiz_tls_server_init(wiz_tls_context* tlsContext, int* socket_fd) {
    int ret = 1;
    const char *pers = "https_server";

    psa_status_t psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        PRT_SSL(" failed\r\n  ! psa_crypto_init returned %d\r\n", (int)psa_status);
        return -1;
    }

#if defined (MBEDTLS_ENTROPY_C)
    tlsContext->entropy = pvPortMalloc(sizeof(mbedtls_entropy_context));
#endif
    tlsContext->ctr_drbg = pvPortMalloc(sizeof(mbedtls_ctr_drbg_context));
    tlsContext->ssl = pvPortMalloc(sizeof(mbedtls_ssl_context));
    tlsContext->conf = pvPortMalloc(sizeof(mbedtls_ssl_config));
    tlsContext->cacert = pvPortMalloc(sizeof(mbedtls_x509_crt));
    tlsContext->clicert = pvPortMalloc(sizeof(mbedtls_x509_crt));
    tlsContext->pkey = pvPortMalloc(sizeof(mbedtls_pk_context));

    if (!tlsContext->ctr_drbg || !tlsContext->ssl || !tlsContext->conf ||
            !tlsContext->cacert || !tlsContext->clicert || !tlsContext->pkey
#if defined (MBEDTLS_ENTROPY_C)
            || !tlsContext->entropy
#endif
       ) {
        PRT_SSL(" failed\r\n  ! HTTPS server memory allocation failed\r\n");
        return -1;
    }

#if defined (MBEDTLS_ENTROPY_C)
    mbedtls_entropy_init(tlsContext->entropy);
#endif
    mbedtls_ctr_drbg_init(tlsContext->ctr_drbg);
    mbedtls_ssl_init(tlsContext->ssl);
    mbedtls_ssl_config_init(tlsContext->conf);
    mbedtls_x509_crt_init(tlsContext->cacert);
    mbedtls_x509_crt_init(tlsContext->clicert);
    mbedtls_pk_init(tlsContext->pkey);

#if defined (MBEDTLS_ENTROPY_C)
    ret = mbedtls_ctr_drbg_seed(tlsContext->ctr_drbg, mbedtls_entropy_func,
                                tlsContext->entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        PRT_SSL(" failed\r\n  ! mbedtls_ctr_drbg_seed returned -0x%x\r\n", -ret);
        return -1;
    }
#endif

    ret = mbedtls_x509_crt_parse(tlsContext->clicert,
                                 (const unsigned char *)HTTPS_SERVER_CERT,
                                 sizeof(HTTPS_SERVER_CERT));
    if (ret != 0) {
        PRT_SSL(" failed\r\n  ! HTTPS server cert parse returned -0x%x\r\n", -ret);
        return -1;
    }

    ret = mbedtls_pk_parse_key(tlsContext->pkey,
                               (const unsigned char *)HTTPS_SERVER_KEY,
                               sizeof(HTTPS_SERVER_KEY),
                               NULL, 0,
                               mbedtls_ctr_drbg_random,
                               tlsContext->ctr_drbg);
    if (ret != 0) {
        PRT_SSL(" failed\r\n  ! HTTPS server key parse returned -0x%x\r\n", -ret);
        return -1;
    }

    ret = mbedtls_ssl_config_defaults(tlsContext->conf,
                                      MBEDTLS_SSL_IS_SERVER,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        PRT_SSL(" failed\r\n  ! mbedtls_ssl_config_defaults returned -0x%x\r\n", -ret);
        return -1;
    }

    mbedtls_ssl_conf_min_tls_version(tlsContext->conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(tlsContext->conf, MBEDTLS_SSL_VERSION_TLS1_2);

    mbedtls_ssl_conf_authmode(tlsContext->conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(tlsContext->conf, mbedtls_ctr_drbg_random, tlsContext->ctr_drbg);
    mbedtls_ssl_conf_read_timeout(tlsContext->conf, 2000);

    /*  정적 RSA 키교환만 허용.
        ECDHE 계열은 RP2040 소프트웨어 EC 연산 때문에 핸드셰이크가 수 초씩
        걸리므로 차단한다. (RSA-only + 세션 캐시 → 재연결 수십 ms) */
    static const int https_ciphersuites[] = {
        MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
        MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
        MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
        0
    };
    mbedtls_ssl_conf_ciphersuites(tlsContext->conf, https_ciphersuites);

    ret = mbedtls_ssl_conf_own_cert(tlsContext->conf, tlsContext->clicert, tlsContext->pkey);
    if (ret != 0) {
        PRT_SSL(" failed\r\n  ! mbedtls_ssl_conf_own_cert returned -0x%x\r\n", -ret);
        return -1;
    }

    if (!https_session_cache_initialized) {
        mbedtls_ssl_cache_init(&https_session_cache);
        https_session_cache_initialized = 1;
    }
    mbedtls_ssl_conf_session_cache(tlsContext->conf,
                                   &https_session_cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set);

    ret = mbedtls_ssl_setup(tlsContext->ssl, tlsContext->conf);
    if (ret != 0) {
        PRT_SSL(" failed\r\n  ! mbedtls_ssl_setup returned -0x%x\r\n", -ret);
        return -1;
    }

    tlsContext->socket_fd = (uint8_t)(*socket_fd);
    mbedtls_ssl_set_bio(tlsContext->ssl,
                        (void *)(uintptr_t)tlsContext->socket_fd,
                        SSLSendCB, SSLRecvCB, SSLRecvTimeOutCB);
    return 1;
}

/*Free the memory for ssl context*/
void wiz_tls_deinit(wiz_tls_context* tlsContext) {
    /*  free SSL context memory  */

    PRT_SSL("SSL Free\r\n");
    if (tlsContext->ssl) {
        mbedtls_ssl_free(tlsContext->ssl);
    }
    if (tlsContext->conf) {
        mbedtls_ssl_config_free(tlsContext->conf);
    }
    if (tlsContext->ctr_drbg) {
        mbedtls_ctr_drbg_free(tlsContext->ctr_drbg);
    }
#if defined (MBEDTLS_ENTROPY_C)
    if (tlsContext->entropy) {
        mbedtls_entropy_free(tlsContext->entropy);
    }
#endif
    if (tlsContext->cacert) {
        mbedtls_x509_crt_free(tlsContext->cacert);
    }
    if (tlsContext->clicert) {
        mbedtls_x509_crt_free(tlsContext->clicert);
    }
    if (tlsContext->pkey) {
        mbedtls_pk_free(tlsContext->pkey);
    }

#if defined (MBEDTLS_ENTROPY_C)
    if (tlsContext->entropy) {
        vPortFree(tlsContext->entropy);
        tlsContext->entropy = NULL;
    }
#endif
    if (tlsContext->ctr_drbg) {
        vPortFree(tlsContext->ctr_drbg);
        tlsContext->ctr_drbg = NULL;
    }
    if (tlsContext->ssl) {
        vPortFree(tlsContext->ssl);
        tlsContext->ssl = NULL;
    }
    if (tlsContext->conf) {
        vPortFree(tlsContext->conf);
        tlsContext->conf = NULL;
    }
    if (tlsContext->cacert) {
        vPortFree(tlsContext->cacert);
        tlsContext->cacert = NULL;
    }
    if (tlsContext->clicert) {
        vPortFree(tlsContext->clicert);
        tlsContext->clicert = NULL;
    }
    if (tlsContext->pkey) {
        vPortFree(tlsContext->pkey);
        tlsContext->pkey = NULL;
    }
}

int wiz_tls_socket(wiz_tls_context* tlsContext, uint8_t sock, unsigned int port) {
    /*socket open*/
    tlsContext->socket_fd = sock;
    //return socket((uint8_t)(tlsContext->socket_fd), Sn_MR_TCP, (uint16_t)port, (SF_TCP_NODELAY | SF_IO_NONBLOCK));
    return socket((uint8_t)(tlsContext->socket_fd), Sn_MR_TCP, (uint16_t)port, 0x00);
}

int wiz_tls_connect(wiz_tls_context* tlsContext, char * addr, unsigned int port) {
    int ret;
    uint32_t flags;
    struct __ssl_option *ssl_option = (struct __ssl_option *) & (get_DevConfig_pointer()->ssl_option);

    PRT_SSL(" Performing the SSL/TLS handshake...\r\n");

    while ((ret = mbedtls_ssl_handshake(tlsContext->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            //mbedtls_strerror(ret, (char *) tempBuf, DEBUG_BUFFER_SIZE );
            //PRT_SSL( " failed\n\r  ! mbedtls_ssl_handshake returned %d: %s\n\r", ret, tempBuf );
            PRT_SSL(" failed\n\r  ! mbedtls_ssl_handshake returned -0x%x\n\r", -ret);
            return (-1);
        }
        vTaskDelay(10);
    }

    if (ssl_option->root_ca_option == MBEDTLS_SSL_VERIFY_REQUIRED) {
        PRT_SSL("  . Verifying peer X.509 certificate...\r\n");

        /* In real life, we probably want to bail out when ret != 0 */
        if ((flags = mbedtls_ssl_get_verify_result(tlsContext->ssl)) != 0) {
            char vrfy_buf[512];
            PRT_SSL("failed\r\n");
            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
            PRT_SSL("%s\r\n", vrfy_buf);
            return -1;
        } else {
            PRT_SSL("ok\r\n");
        }
    }
    PRT_SSL(" ok\n\r    [ Ciphersuite is %s ]\n\r",
            mbedtls_ssl_get_ciphersuite(tlsContext->ssl));
    return (0);
}

int wiz_tls_server_handshake(wiz_tls_context* tlsContext) {
    int ret;
    uint32_t start_ms = millis();
    uint32_t last_log_ms = start_ms;
    uint8_t sock = tlsContext->socket_fd;

    PRT_SSL(" Performing the HTTPS server handshake...\r\n");
    while ((ret = mbedtls_ssl_handshake(tlsContext->ssl)) != 0) {
        device_wdt_reset();

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            PRT_SSL(" failed\r\n  ! mbedtls_ssl_handshake returned -0x%x\r\n", -ret);
            return -1;
        }

        uint8_t sr = getSn_SR(sock);
        if (sr == SOCK_CLOSED || sr == SOCK_CLOSE_WAIT) {
            PRT_SSL(" failed\r\n  ! Socket closed during handshake sock=%d\r\n", sock);
            return -1;
        }

        if ((millis() - last_log_ms) >= 500) {
            PRT_SSL(" handshake pending ret=-0x%x sock=%d sr=0x%02x rx=%d\r\n",
                    -ret, sock, getSn_SR(sock), getSn_RX_RSR(sock));
            last_log_ms = millis();
        }

        if ((millis() - start_ms) >= 5000) {
            PRT_SSL(" failed\r\n  ! HTTPS server handshake timeout sock=%d sr=0x%02x rx=%d\r\n",
                    sock, getSn_SR(sock), getSn_RX_RSR(sock));
            return -1;
        }

        vTaskDelay(10);
    }

    PRT_SSL(" ok\r\n    [ HTTPS server ciphersuite is %s ]\r\n",
            mbedtls_ssl_get_ciphersuite(tlsContext->ssl));
    return 0;
}

/* SSL handshake */
int wiz_tls_socket_connect(wiz_tls_context* tlsContext, char * addr, unsigned int port) {
    int ret;
    uint8_t sock = (uint8_t)(tlsContext->socket_fd);

#if defined(MBEDTLS_ERROR_C)
    char error_buf[1024];
#endif
    /*socket open*/
    ret = socket(sock, Sn_MR_TCP, 0, 0x00);
    if (ret != sock) {
        return ret;
    }

    /*Connect to the target*/
    ret = connect(sock, addr, port);
    if (ret != SOCK_OK) {
        return ret;
    }

#if defined(MBEDTLS_DEBUG_C)
    printf(" Performing the SSL/TLS handshake...\r\n");
#endif

    while ((ret = mbedtls_ssl_handshake(tlsContext->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
#if defined(MBEDTLS_ERROR_C)
            memset(error_buf, 0, 1024);
            mbedtls_strerror(ret, (char *) error_buf, DEBUG_BUFFER_SIZE);
            printf(" failed\n\r  ! mbedtls_ssl_handshake returned %d: %s\n\r", ret, error_buf);
#endif
            return (-1);
        }
    }

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok\n\r    [ Ciphersuite is %s ]\n\r",
           mbedtls_ssl_get_ciphersuite(tlsContext->ssl));
#endif

    return (0);
}

int wiz_tls_close(wiz_tls_context* tlsContext) {
    uint8_t sock = (uint8_t)(tlsContext->socket_fd);

    wiz_tls_close_notify(tlsContext);
    wiz_tls_session_reset(tlsContext);
    wiz_tls_deinit(tlsContext);

    close(sock);
    set_wiz_tls_init_state(DISABLE);

    return (0);
}

unsigned int wiz_tls_read(wiz_tls_context* tlsContext, unsigned char* readbuf, unsigned int len) {
    return mbedtls_ssl_read(tlsContext->ssl, readbuf, len);
}

unsigned int wiz_tls_write(wiz_tls_context* tlsContext, unsigned char* writebuf, unsigned int len) {
    return mbedtls_ssl_write(tlsContext->ssl, writebuf, len);
}

int wiz_tls_disconnect(wiz_tls_context* tlsContext, uint32_t timeout) {
    int ret = 0;
    uint8_t sock = (uint8_t)(tlsContext->socket_fd);
    uint32_t tickStart = millis();

    do {
        ret = disconnect(sock);
        if ((ret == SOCK_OK) || (ret == SOCKERR_TIMEOUT)) {
            break;
        }
    } while ((millis() - tickStart) < timeout);

    if (ret == SOCK_OK) {
        ret = sock;    // socket number
    }

    return ret;
}


/* ssl Close notify */
unsigned int wiz_tls_close_notify(wiz_tls_context* tlsContext) {
    uint32_t rc;
    do {
        device_wdt_reset();
        rc = mbedtls_ssl_close_notify(tlsContext->ssl);
    } while (rc == MBEDTLS_ERR_SSL_WANT_WRITE);
    return rc;
}


/* ssl session reset */
int wiz_tls_session_reset(wiz_tls_context* tlsContext) {
    return mbedtls_ssl_session_reset(tlsContext->ssl);
}


int check_ca(uint8_t *ca_data, uint32_t ca_len) {
    int ret;

    mbedtls_x509_crt ca_cert;
    mbedtls_x509_crt_init(&ca_cert);


    //PRT_SSL("ca_len = %d\r\n", ca_len);
    ret = mbedtls_x509_crt_parse(&ca_cert, (const char *)ca_data, ca_len + 1);
    if (ret < 0) {
        PRT_SSL(" failed\r\n  !  mbedtls_x509_crt_parse returned -0x%x while parsing root cert\r\n", -ret);
    } else {
        PRT_SSL("ok! mbedtls_x509_crt_parse returned -0x%x while parsing root cert\r\n", -ret);
    }

    mbedtls_x509_crt_free(&ca_cert);
    return ret;
}

int check_pkey(wiz_tls_context* tlsContext, uint8_t *pkey_data, uint32_t pkey_len) {
    int ret;

    mbedtls_pk_context pk_cert;
    mbedtls_pk_init(&pk_cert);

    //PRT_SSL("pkey_len = %d\r\n", pkey_len);

    ret = mbedtls_pk_parse_key(&pk_cert, (const char *)pkey_data, pkey_len + 1, NULL, 0, mbedtls_ctr_drbg_random, tlsContext->ctr_drbg);
    if (ret != 0) {
        PRT_SSL(" failed\r\n  !  mbedtls_pk_parse_key returned -0x%x while parsing private key\r\n", -ret);
    } else {
        PRT_SSL(" ok !  mbedtls_pk_parse_key returned -0x%x while parsing private key\r\n", -ret);
    }

    mbedtls_pk_free(&pk_cert);
    return ret;
}

int get_wiz_tls_init_state(void) {
    return wiz_tls_init_state;
}


void set_wiz_tls_init_state(int state) {
    if (state > 0) {
        wiz_tls_init_state = ENABLE;
    } else {
        wiz_tls_init_state = DISABLE;
    }
}
