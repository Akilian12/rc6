#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libakrypt.h>


static ak_uint8 keyAnnexA[32] = {
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

static ak_uint8 associated[41] = {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0xEA };

static ak_uint8 plain[67] = {
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x11, 0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
        0xCC, 0xBB, 0xAA };

static ak_uint8 iv128[16] = {
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };

static ak_uint8 icodeOne[16] = {
        0xD5, 0x95, 0xff, 0x38, 0x20, 0x7E, 0xE3, 0x9C, 0x27, 0x67, 0x61, 0xFD, 0xA0, 0xD1, 0xD4, 0xF4 };

int main( void )
{
    int result;
    struct bckey key; /* ключ блочного алгоритма шифрования */
    ak_uint8 frame[124];

    /* инициализируем библиотеку */
    if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();
    ak_libakrypt_set_openssl_compability( ak_false );
    /* контрольный пример расчитан для несовместимого режима */
    /* формируем фрейм */
    memcpy( frame, associated, sizeof ( associated ));        /* ассоциированные данные */
    memcpy( frame + sizeof( associated ), plain, sizeof( plain ));  /* шифруемые данные */
    memset( frame + ( sizeof( associated ) + sizeof( plain )), 0, 16 ); /* имитовставка */

    /* инициализируем ключ */
    ak_bckey_create_rc6( &key );
    ak_bckey_set_key( &key, keyAnnexA, sizeof( keyAnnexA ));

    /* зашифровываем данные и одновременно вычисляем имитовставку */
    ak_bckey_encrypt_mgm(
            &key,              /* ключ, используемый для шифрования данных */
            &key,             /* ключ, используемый для имитозащиты данных */
            frame,                  /* указатель на ассоциированные данные */
            sizeof( associated ),          /* длина ассоциированных данных */
            plain,                  /* указатель на зашифровываемые данные */
            frame + sizeof( associated ),   /* указатель на область памяти,
                         в которую помещаются зашифрованные данные */
            sizeof( plain ),              /* размер зашифровываемых данных */
            iv128,             /* синхропосылка (инициализационный вектор) */
            sizeof( iv128 ),                       /* размер синхропосылки */
            /* указатель на область памяти,
         в которую помещается имитовставка */
            frame + sizeof( associated ) + sizeof( plain ),
            16                                      /* размер имитовставки */
    );

    /* выводим результат и проверяем полученное значение */
    printf("encrypted frame: %s [", ak_ptr_to_hexstr( frame, sizeof( frame ), ak_false ));
    if( memcmp( frame + sizeof( associated ) + sizeof( plain ), icodeOne, 16 )) {

        printf(" Wrong]\n");
        printf("frame: %s\n",
               ak_ptr_to_hexstr( frame + sizeof( associated ) + sizeof( plain ), 16, ak_false ));
        printf("icode: %s\n", ak_ptr_to_hexstr( icodeOne, 16, ak_false ));
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    } else printf(" Ok]\n\n");

    /* расшифровываем и проверяем имитовставку */
    result = ak_bckey_decrypt_mgm(
            &key,           /* ключ, используемый для расшифрования данных */
            &key,             /* ключ, используемый для имитозащиты данных */
            frame,                  /* указатель на ассоциированные данные */
            sizeof( associated ),          /* длина ассоциированных данных */
            /* указатель на расшифровываемые данные */
            frame + sizeof( associated),
            frame + sizeof( associated ),   /* указатель на область памяти,
                        в которую помещаются расшифрованные данные */
            sizeof( plain ),                /* размер зашифрованных данных */
            iv128,             /* синхропосылка (инициализационный вектор) */
            sizeof( iv128 ),                       /* размер синхропосылки */
            /* указатель на область памяти,
в которой находится вычисленная ранее имитовставка
(с данным значением производится сравнение) */
            frame + sizeof( associated ) + sizeof( plain ),
            16                                      /* размер имитовставки */
    );

    printf("decrypted frame: %s [", ak_ptr_to_hexstr( frame, sizeof( frame ), ak_false ));
    if( result == ak_error_ok ) printf("Correct]\n");
    else printf("Incorrect]\n");

    /* уничтожаем контекст ключа */
    ak_bckey_destroy( &key );
    ak_libakrypt_destroy();

    if( result == ak_error_ok ) return EXIT_SUCCESS;
    else return EXIT_FAILURE;
}
