/* ----------------------------------------------------------------------------------------------- */
/*                                                                                                 */
/*  Файл ak_rc6.c                                                                                  */
/*  - содержит реализацию алгоритма блочного шифрования RC6                                        */
/* ----------------------------------------------------------------------------------------------- */
#include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Развернутые раундовые ключи алгоритма RC6. */
typedef ak_uint32 ak_rc6_expanded_keys[44];

/* ---------------------------------------------------------------------------------------------- */
static const ak_uint32 ak_rc6_rounds = 20;
static const ak_uint32 ak_rc6_key_len = 256;
static const ak_uint32 ak_rc6_p32 = 0xB7E15163;
static const ak_uint32 ak_rc6_q32 = 0x9E3779B9;
static const ak_uint32 ak_rc6_lg_w = 5;
/* ----------------------------------------------------------------------------------------------- */
/*                                Вспомогательные функции                                          */
/* ----------------------------------------------------------------------------------------------- */
static ak_uint32 ak_rc6_left_bit_cicl_shift(ak_uint32 val, ak_uint32 bit_count){
    return (val << bit_count) | (val >> (32 - bit_count));
}
/* ----------------------------------------------------------------------------------------------- */
static ak_uint32 ak_rc6_right_bit_cicl_shift(ak_uint32 val, ak_uint32 bit_count){
    return (val >> bit_count) | (val << (32 - bit_count));
}
/* ----------------------------------------------------------------------------------------------- */
/* ----------------------------------------------------------------------------------------------- */
/*                                функции для работы с контекстом                                  */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция освобождает память, занимаемую развернутыми ключами алгоритма RC6.
    \param skey Указатель на контекст секретного ключа, содержащего развернутые
    раундовые ключи и маски.
    \return Функция возвращает \ref ak_error_ok в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
static int ak_rc6_delete_keys( ak_skey skey )
{
    int error = ak_error_ok;

    /* выполняем стандартные проверки */
    if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                                __func__ , "using a null pointer to secret key" );
    if( skey->data != NULL ) {
        /* теперь очистка и освобождение памяти */
        if(( error = ak_ptr_wipe( skey->data, sizeof( ak_rc6_expanded_keys ),
                                  &skey->generator )) != ak_error_ok ) {
            ak_error_message( error, __func__, "incorrect wiping an internal data" );
            memset( skey->data, 0, sizeof( ak_rc6_expanded_keys ));
        }
        free( skey->data );
        skey->data = NULL;
    }
    return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует развертку ключей для алгоритма RC6.
    \param skey Указатель на контекст секретного ключа, в который помещаются развернутые
    раундовые ключи и маски.
    \return Функция возвращает \ref ak_error_ok в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
static int ak_rc6_schedule_keys( ak_skey skey )
{
    /* выполняем стандартные проверки */
    if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                "using a null pointer to secret key" );
    if( skey->key_size != 32 ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "unsupported length of secret key" );
    /* проверяем целостность ключа */
    if( skey->check_icode( skey ) != ak_true ) return ak_error_message( ak_error_wrong_key_icode,
                                                                        __func__ , "using key with wrong integrity code" );
    /* удаляем былое */
    if( skey->data != NULL ) ak_rc6_delete_keys( skey );

    /* далее, по-возможности, выделяем выравненную память */
    if(( skey->data = ak_aligned_malloc( sizeof( ak_rc6_expanded_keys ))) == NULL )
        return ak_error_message( ak_error_out_of_memory, __func__ ,
                                 "wrong allocation of internal data" );

    ak_uint32 i = 0, j = 0, k = 0, A = 0, B = 0;
    ak_uint32 *result = ( ak_uint32 *)skey->data;
    ak_uint32 L[8] = {0};

    result[0] = ak_rc6_p32;
    for (i = 1; i < 2 * ak_rc6_rounds + 4; ++i){
        result[i] = result[i - 1] + ak_rc6_q32;
    }
    i = 0;
    for (k = 1; k <= 3 * (2 * ak_rc6_rounds + 4); ++k){
        A = result[i] = ak_rc6_left_bit_cicl_shift(result[i] + A + B, 3);
        B = L[j] = ak_rc6_left_bit_cicl_shift((L[j] + A + B), A + B);
        i = (i + 1) % (2 * ak_rc6_rounds + 4);
        j = (j + 1) % 8;
    }

    ak_ptr_wipe(L, sizeof(L), &skey->generator);
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм зашифрования одного блока информации
    шифром RC6.                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
static void ak_rc6_encrypt( ak_skey skey, ak_pointer in, ak_pointer out )
{
    int i = 0;
    ak_uint32 *keys = (ak_uint32*)skey->data;
    ak_uint32 A = ((ak_uint32 *)in)[0], B = ((ak_uint32 *)in)[1], C = ((ak_uint32 *)in)[2], D = ((ak_uint32 *)in)[3];
    ak_uint32 t, u, tmp;

    B = B + keys[0];
    D = D + keys[1];
    for(i = 1; i <= ak_rc6_rounds; ++i){
        t = ak_rc6_left_bit_cicl_shift((B * (2 * B + 1)), ak_rc6_lg_w);
        u = ak_rc6_left_bit_cicl_shift((D * (2 * D + 1)), ak_rc6_lg_w);
        A = ak_rc6_left_bit_cicl_shift(A ^ t, u) + keys[2 * i];
        C = ak_rc6_left_bit_cicl_shift(C ^ u, t) + keys[2 * i + 1];
        tmp = A; A = B; B = C; C = D; D = tmp;
    }
    A = A + keys[2 * ak_rc6_rounds + 2];
    C = C + keys[2 * ak_rc6_rounds + 3];
    ((ak_uint32 *)out)[0] = A;
    ((ak_uint32 *)out)[1] = B;
    ((ak_uint32 *)out)[2] = C;
    ((ak_uint32 *)out)[3] = D;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм расшифрования одного блока информации
    шифром RC6.                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
static void ak_rc6_decrypt( ak_skey skey, ak_pointer in, ak_pointer out )
{
    int i = 0;
    ak_uint32 *keys = (ak_uint32*)skey->data;
    ak_uint32 A = ((ak_uint32 *)in)[0], B = ((ak_uint32 *)in)[1], C = ((ak_uint32 *)in)[2], D = ((ak_uint32 *)in)[3];
    ak_uint32 t, u, tmp;

    C = C - keys[2 * ak_rc6_rounds + 3];
    A = A - keys[2 * ak_rc6_rounds + 2];
    for (i = ak_rc6_rounds; i >= 1; --i){
        tmp = D; D = C; C = B; B = A; A = tmp;
        u = ak_rc6_left_bit_cicl_shift(D * (2 * D + 1), ak_rc6_lg_w);
        t = ak_rc6_left_bit_cicl_shift(B * (2 * B + 1), ak_rc6_lg_w);
        C = ak_rc6_right_bit_cicl_shift(C - keys[2 * i + 1], t) ^ u;
        A = ak_rc6_right_bit_cicl_shift(A - keys[2 * i], u) ^ t;
    }
    D = D - keys[1];
    B = B - keys[0];

    ((ak_uint32 *)out)[0] = A;
    ((ak_uint32 *)out)[1] = B;
    ((ak_uint32 *)out)[2] = C;
    ((ak_uint32 *)out)[3] = D;
}

/* ----------------------------------------------------------------------------------------------- */

/*! После инициализации устанавливаются обработчики (функции класса). Однако само значение
    ключу не присваивается - поле `bkey->key` остается неопределенным.

    \param bkey Контекст секретного ключа алгоритма блочного шифрования.
    \return Функция возвращает код ошибки. В случаее успеха возвращается \ref ak_error_ok.         */
/* ----------------------------------------------------------------------------------------------- */
int ak_bckey_create_rc6( ak_bckey bkey )
{
    int error = ak_error_ok, oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" );

    if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                "using null pointer to block cipher key context" );
    if(( oc < 0 ) || ( oc > 1 )) return ak_error_message( ak_error_wrong_option, __func__,
                                                          "wrong value for \"openssl_compability\" option" );

    /* создаем ключ алгоритма шифрования и определяем его методы */
    if(( error = ak_bckey_create( bkey, 32, 16 )) != ak_error_ok )
        return ak_error_message( error, __func__, "wrong initalization of block cipher key context" );

    /* устанавливаем OID алгоритма шифрования */
    if(( bkey->key.oid = ak_oid_find_by_name( "rc6" )) == NULL ) {
        ak_error_message( error = ak_error_get_value(), __func__,
                          "wrong search of predefined rc6 block cipher OID" );
        ak_bckey_destroy( bkey );
        return error;
    }


    /* ресурс ключа устанавливается в момент присвоения ключа */

    /* устанавливаем методы */
    bkey->schedule_keys = ak_rc6_schedule_keys;
    bkey->delete_keys = ak_rc6_delete_keys;
    if( oc ) {
        bkey->encrypt = ak_rc6_encrypt;
        bkey->decrypt = ak_rc6_decrypt;
    }
    else {
        bkey->encrypt = ak_rc6_encrypt;
        bkey->decrypt = ak_rc6_decrypt;
    }
    return error;
}
/* ----------------------------------------------------------------------------------------------- */
/* ----------------------------------------------------------------------------------------------- */
/*                                      функции тестирования                                       */
/* ----------------------------------------------------------------------------------------------- */
static bool_t ak_libakrypt_test_rc6_complete( void )
{
    struct bckey bkey;
    ak_uint8 myout[256];
    bool_t result = ak_true;
    int error = ak_error_ok, audit = ak_log_get_level(),
            oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" );

    /* тестовый ключ из ГОСТ Р 34.13-2015, приложение А.1 */
    ak_uint8 key[32] = {
            0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01,0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
            0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88
    };


    /* открытый текст из ГОСТ Р 34.13-2015, приложение А.1, подлежащий зашифрованию
       первый блок совпадает с блоком тестовых данных из ГОСТ Р 34.12-2015          */
    ak_uint8 in[64] = {
            0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x77,0x66,0x55,0x44,0x33,0x22,0x11,
            0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
            0x00,0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,
            0x11,0x00,0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22
    };


    /* результат простой замены */
    ak_uint8 outecb[64] = {
            0x21, 0x9b, 0x58, 0x7d, 0xfb, 0xc5, 0xb4, 0xc4, 0xb2, 0x43, 0xf3, 0x6, 0x19, 0x44, 0x28, 0xe, 0x2d, 0x29, 0x54, 0xc7, 0x6a,
            0xd2, 0x8e, 0xce, 0x7b, 0x54, 0x26, 0x59, 0xb7, 0xfd, 0x17, 0xc1, 0xb, 0x7a, 0xf4, 0xba, 0xba, 0x68, 0x47, 0xa1, 0xf8, 0xe9,
            0x62, 0xde, 0xf3, 0x40, 0x25, 0xe9, 0x7f, 0xb0, 0x5e, 0xad, 0x4a, 0x6e, 0x7f, 0xe0, 0xf1, 0xde, 0x49, 0x7f, 0xd2, 0x13, 0x13, 0xb3
    };

    /* инициализационный вектор для режима гаммирования (счетчика) */
    ak_uint8 ivctr[8] = { 0xf0,0xce,0xab,0x90,0x78,0x56,0x34,0x12 };

    /* результат применения режима гаммирования из ГОСТ Р 34.12-2015 */
    ak_uint8 outctr[64] = {
            0xa8, 0x12, 0x9f, 0x8a, 0xaf, 0xc0, 0x89, 0x62, 0xa8, 0x95, 0xa1, 0x8e, 0xa7, 0xd5, 0x73, 0x20, 0xd4, 0x15, 0x4e, 0x59,
            0x31, 0x4a, 0x33, 0x64, 0x81, 0x2d, 0x84, 0xca, 0x3, 0x99, 0x33, 0x9b, 0x90, 0x82, 0xc, 0x25, 0x67, 0xd6, 0x8a, 0xcf, 0x5e,
            0x5a, 0xd8, 0x8, 0x9c, 0xef, 0x58, 0xef, 0x7e, 0x31, 0xb0, 0x94, 0xf8, 0xc6, 0x2a, 0x0, 0xac, 0xc, 0xc1, 0xed, 0x4d,
            0xcc, 0x29, 0x83
    };

    /* инициализационный вектор для режима простой замены с зацеплением */
    ak_uint8 ivcbc[32] = {
            0x12, 0x01, 0xf0, 0xe5, 0xd4, 0xc3, 0xb2, 0xa1, 0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
            0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x90, 0x89, 0x78, 0x67, 0x56, 0x45, 0x34, 0x23
    };

    /* зашифрованный блок из ГОСТ Р 34.12-2015 для режима простой замены с зацеплением */
    ak_uint8 outcbc[64] = {
            0xb6, 0x54, 0xca, 0xc5, 0xb3, 0x77, 0x55, 0xeb, 0x32, 0x9f, 0xae, 0xb1, 0x99, 0x58, 0xe3, 0xa4, 0xf5, 0xad, 0x4d, 0xdc,
            0xd, 0x26, 0xcf, 0xa7, 0x50, 0x7a, 0x0, 0xe3, 0xb9, 0x80, 0x5a, 0x14, 0x88, 0x99, 0x12, 0xa4, 0xeb, 0xf0, 0xf2, 0xd4, 0xf6,
            0x51, 0xfe, 0x8, 0x2d, 0x31, 0x30, 0x29, 0x99, 0xa5, 0x94, 0x30, 0x2c, 0x7, 0x50, 0x5e, 0x5e, 0x2c, 0x63, 0xeb, 0xf1
            , 0xee, 0x29, 0xeb
    };

    /* инициализационный вектор для режима гаммирования с обратной связью по выходу (ofb) */
    ak_uint8 ivofb[32] = {
            0x12, 0x01, 0xf0, 0xe5, 0xd4, 0xc3, 0xb2, 0xa1, 0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
            0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x90, 0x89, 0x78, 0x67, 0x56, 0x45, 0x34, 0x23
    };


    /* зашифрованный блок из ГОСТ Р 34.13-2015, прил. А.1.3*/
    ak_uint8 outofb[64] = {
            0xee, 0x6, 0x98, 0x2b, 0xa7, 0x2f, 0x6e, 0x23, 0x13, 0xe3, 0x10, 0x9c, 0x3a, 0x4c, 0xef, 0xd0, 0x38, 0x65, 0xae, 0xf2, 0x82,
            0x6c, 0xcf, 0x6f, 0x7f, 0xc7, 0xa8, 0xed, 0xe6, 0xb8, 0x38, 0x76, 0xe4, 0x4d, 0xcf, 0xbc, 0xb1, 0xe1, 0xd6, 0x8b, 0x8e,
            0x21, 0xef, 0x39, 0xeb, 0x8f, 0xfe, 0x81, 0x1d, 0x6c, 0xfb, 0x95, 0x91, 0x81, 0xef, 0x35, 0xdf, 0xfe, 0xf3, 0x2d, 0xf0, 0xa7, 0xe6, 0xd9
    };

    /* зашифрованный блок из ГОСТ Р 34.13-2015, прил. А.1.5 */
    ak_uint8 outcfb[64] = {
            0xee, 0x6, 0x98, 0x2b, 0xa7, 0x2f, 0x6e, 0x23, 0x13, 0xe3, 0x10, 0x9c, 0x3a, 0x4c, 0xef, 0xd0, 0x38, 0x65, 0xae, 0xf2, 0x82,
            0x6c, 0xcf, 0x6f, 0x7f, 0xc7, 0xa8, 0xed, 0xe6, 0xb8, 0x38, 0x76, 0xfa, 0x44, 0xa3, 0x33, 0x91, 0x94, 0x66, 0x31, 0x31,
            0x25, 0xc0, 0x2b, 0xe1, 0xbe, 0xc8, 0x43, 0xfc, 0x4e, 0x4c, 0x9c, 0x2d, 0xa, 0x4, 0x64, 0x3e, 0x40, 0xfd, 0xf1, 0x3c, 0x2a, 0xc, 0x3e
    };

    /* значение имитовставки согласно ГОСТ Р 34.13-2015 (раздел А.1.6) */
    ak_uint8 imito[8] = {
            /* 0x67, 0x9C, 0x74, 0x37, 0x5B, 0xB3, 0xDE, 0x4D - первая часть выработанного блока */
            0x77, 0xa8, 0xf2, 0x77, 0x69, 0x68, 0x9c, 0x37
    };

    /* Проверка используемого режима совместимости */
    if(( oc < 0 ) || ( oc > 1 )) {
        ak_error_message( ak_error_wrong_option, __func__,
                          "wrong value for \"openssl_compability\" option" );
        return ak_false;
    }

    if( result != ak_true ) {
        ak_error_message( ak_error_invalid_value, __func__,
                          "incorrect constant values for rc6 secret key" );
        return ak_false;
    }

    /* --------------------------------------------------------------------------- */
    /* 1. Создаем контекст ключа алгоритма rc6 и устанавливаем значение ключа */
    /* --------------------------------------------------------------------------- */
    if(( error = ak_bckey_create_rc6( &bkey )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect initialization of rc6 secret key context");
        return ak_false;
    }

    if(( error = ak_bckey_set_key( &bkey, key,
                                   sizeof( key ))) != ak_error_ok ) {
        ak_error_message( error, __func__, "wrong creation of test key" );
        result = ak_false;
        goto exit;
    }

    /* ------------------------------------------------------------------------------------------- */
    /* 2. Проверяем независимую обработку блоков - режим простой замены согласно ГОСТ Р 34.12-2015 */
    /* ------------------------------------------------------------------------------------------- */
    if(( error = ak_bckey_encrypt_ecb( &bkey, in,
                                       myout, sizeof( in ))) != ak_error_ok ) {
        ak_error_message( error, __func__ , "wrong ecb mode encryption" );
        result = ak_false;
        goto exit;
    }

    if( !ak_ptr_is_equal_with_log( myout, outecb, sizeof( outecb ))) {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the ecb mode encryption test from GOST R 34.13-2015 is wrong");
        result = ak_false;
        goto exit;
    }

    if(( error = ak_bckey_decrypt_ecb( &bkey, outecb,
                                       myout, sizeof( outecb ))) != ak_error_ok ) {
        ak_error_message( error, __func__ , "wrong ecb mode decryption" );
        result = ak_false;
        goto exit;
    }
    if( !ak_ptr_is_equal_with_log( myout, in, sizeof( in ))) {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the ecb mode decryption test from GOST R 34.13-2015 is wrong");
        result = ak_false;
        goto exit;
    }
    if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                    "the ecb mode encryption/decryption test from GOST R 34.13-2015 is Ok" );

    /* --------------------------------------------------------------------------- */
    /* 3. Проверяем режим гаммирования согласно ГОСТ Р 34.12-2015                  */
    /* --------------------------------------------------------------------------- */
    if(( error = ak_bckey_ctr( &bkey, in,
                               myout, sizeof( in ), ivctr, sizeof( ivctr ))) != ak_error_ok ) {
        ak_error_message( error, __func__ , "wrong counter mode encryption" );
        result = ak_false;
        goto exit;
    }

    if( !ak_ptr_is_equal_with_log( myout, outctr, sizeof( outecb ))) {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the counter mode encryption test from GOST R 34.13-2015 is wrong");
        result = ak_false;
        goto exit;
    }

    if(( error = ak_bckey_ctr( &bkey, myout,
                               myout, sizeof( outecb ), ivctr, sizeof( ivctr ))) != ak_error_ok ) {
        ak_error_message( error, __func__ , "wrong counter mode decryption" );
        result = ak_false;
        goto exit;
    }
    if( !ak_ptr_is_equal_with_log( myout, in, sizeof( in ))) {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the counter mode decryption test from GOST R 34.13-2015 is wrong");
        result = ak_false;
        goto exit;
    }
    if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                    "the counter mode encryption/decryption test from GOST R 34.13-2015 is Ok" );

    /* --------------------------------------------------------------------------- */
    /* 4. Проверяем режим простой замены c зацеплением согласно ГОСТ Р 34.12-2015  */
    /* --------------------------------------------------------------------------- */
    if(( error = ak_bckey_encrypt_cbc( &bkey, in, myout, sizeof( in ),
                                       ivcbc, sizeof( ivcbc ))) != ak_error_ok ) {
        ak_error_message( error, __func__ , "wrong cbc mode encryption" );
        result = ak_false;
        goto exit;
    }

    if( !ak_ptr_is_equal_with_log( myout, outcbc, sizeof( outcbc ))) {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the cbc mode encryption test from GOST R 34.13-2015 is wrong");
        result = ak_false;
        goto exit;
    }
    if(( error = ak_bckey_decrypt_cbc( &bkey, outcbc, myout,
                                       sizeof( outcbc ), ivcbc, sizeof( ivcbc ))) != ak_error_ok ) {
        ak_error_message( error, __func__ , "wrong cbc mode encryption" );
        result = ak_false;
        goto exit;
    }
    if( !ak_ptr_is_equal_with_log( myout, in, sizeof( in ))) {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the cbc mode encryption test from GOST R 34.13-2015 is wrong");
        result = ak_false;
        goto exit;
    }
    if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                    "the cbc mode encryption/decryption test from GOST R 34.13-2015 is Ok" );

    /* -------------------------------------------------------------------------------------- */
    /* 5. Проверяем режим гаммирования c обратной связью по выходу согласно ГОСТ Р 34.12-2015 */
    /* -------------------------------------------------------------------------------------- */
    if(( error = ak_bckey_ofb( &bkey, in,
                               myout, sizeof( in ), ivofb, sizeof( ivofb ))) != ak_error_ok ) {
        ak_error_message( error, __func__ , "wrong ofb mode encryption" );
        result = ak_false;
        goto exit;
    }

    if( !ak_ptr_is_equal_with_log( myout, outofb, sizeof( outofb ))) {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the ofb mode encryption test from GOST R 34.13-2015 is wrong");
        result = ak_false;
        goto exit;
    }

    if(( error = ak_bckey_ofb( &bkey, outofb,
                               myout, sizeof( outofb ), ivofb, sizeof( ivofb ))) != ak_error_ok ) {
        ak_error_message( error, __func__ , "wrong ofb mode decryption" );
        result = ak_false;
        goto exit;
    }
    if( !ak_ptr_is_equal_with_log( myout, in, sizeof( in ))) {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the ofb mode decryption test from GOST R 34.13-2015 is wrong");
        result = ak_false;
        goto exit;
    }
    if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                    "the ofb mode encryption/decryption test from GOST R 34.13-2015 is Ok" );

    /* -------------------------------------------------------------------------------------- */
    /* 6. Проверяем режим гаммирования c обратной связью по шифртексту */
    /* -------------------------------------------------------------------------------------- */
    if(( error = ak_bckey_encrypt_cfb( &bkey, in,
                                       myout, sizeof( in ), ivofb, sizeof( ivofb ))) != ak_error_ok ) {
        /* используемая синхропосылка совпадает с вектором из режима ofb */
        ak_error_message( error, __func__ , "wrong cfb mode encryption" );
        result = ak_false;
        goto exit;
    }

    if( !ak_ptr_is_equal_with_log( myout, outcfb, sizeof( outcfb ))) {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the cfb mode encryption test from GOST R 34.13-2015 is wrong");
        result = ak_false;
        goto exit;
    }

    if(( error = ak_bckey_decrypt_cfb( &bkey, outcfb,
                                       myout, sizeof( outcfb ), ivofb, sizeof( ivofb ))) != ak_error_ok ) {
        ak_error_message( error, __func__ , "wrong cfb mode decryption" );
        result = ak_false;
        goto exit;
    }
    if( !ak_ptr_is_equal_with_log( myout, in, sizeof( in ))) {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the cfb mode decryption test from GOST R 34.13-2015 is wrong");
        result = ak_false;
        goto exit;
    }
    if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                    "the cfb mode encryption/decryption test from GOST R 34.13-2015 is Ok" );

    /* --------------------------------------------------------------------------- */
    /* 10. Тестируем режим выработки имитовставки (плоская реализация).            */
    /* --------------------------------------------------------------------------- */
    if(( error = ak_bckey_cmac( &bkey, in,
                                sizeof( in ), myout, 8 )) != ak_error_ok ) {
        ak_error_message( error, __func__ , "wrong cmac calculation" );
        result = ak_false;
        goto exit;
    }

    if( !ak_ptr_is_equal_with_log( myout, imito, 8 )) {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the cmac integrity test from GOST R 34.13-2015 is wrong");
        result = ak_false;
        goto exit;
    }
    if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                    "the cmac integrity test from GOST R 34.13-2015 is Ok" );
    /* освобождаем ключ и выходим */
    exit:
    if(( error = ak_bckey_destroy( &bkey )) != ak_error_ok ) {
        ak_error_message( error, __func__, "wrong destroying of secret key" );
        return ak_false;
    }

    return result;
}

/* ----------------------------------------------------------------------------------------------- */
bool_t ak_libakrypt_test_rc6( void )
{
    int audit = audit = ak_log_get_level();

    if( !ak_libakrypt_test_rc6_complete( )) {
        ak_error_message( ak_error_get_value(), __func__,
                          "incorrect testing of rc6 block cipher" );
        return ak_false;
    }

    if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                    "testing of rc6 block ciper is Ok" );
    return ak_true;
}


/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_rc6.c        */
/* ----------------------------------------------------------------------------------------------- */
