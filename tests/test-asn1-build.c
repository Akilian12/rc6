//
// Created by Anton Sakharov on 2019-08-03.
//

#include <stdlib.h>
#include <ak_asn1.h>

 int main(void)
{
  int i = 0;
  ak_uint32 u32 = 0;
  bool_t bool = ak_true;
  ak_uint8 buf[13] = { 0x01, 0x02, 0x03, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xe };
  struct asn1 root, *asn1 = NULL, *asn_down_level = NULL;

 /* Инициализируем библиотеку */
  if( ak_libakrypt_create( NULL ) != ak_true ) return ak_libakrypt_destroy();

  if( ak_asn1_context_create( asn1 = malloc( sizeof( struct asn1 ))) == ak_error_ok )
    printf(" level asn1 created succesfully ... \n");

 /* создаем вложенный уровень дерева, используя указатель asn1,
    и добавляем в него булевы элементы */
  ak_asn1_context_add_bool( asn1, bool ); /* используется инициализированная ячейка памяти */
  ak_asn1_context_add_bool( asn1, ak_false ); /* используется константа */

   /* иллюстрируем доступ к данным, хранящимся в узлах дерева
      и проверяем значение последней булевой переменной */
     if( ak_tlv_context_get_bool( asn1->current, &bool ) == ak_error_ok )
       printf(" bool variable: %u (must be false)\n", bool );

 /* добавляем во вложенный уровень целые, 32-х битные числа */
  ak_asn1_context_add_uint32( asn1, 0x8FFFFFFa ); /* используется константа,
                                           которая должна занимать в памяти 5 октетов */
  ak_asn1_context_add_uint32( asn1, 8388607 ); /* используется константа,
                                            которая должна занимать в памяти 3 октета */
  ak_asn1_context_add_uint32( asn1, 254 ); /* используется константа,
                                            которая должна занимать в памяти 2 октета */
  ak_asn1_context_add_uint32( asn1, 17 ); /* используется константа,
                                             которая должна занимать в памяти 1 октет */

   /* иллюстрируем доступ к данным, хранящимся в узлах дерева
      и проверяем добавленные значения */
      for( i = 0; i < 4; i++ ) {
         if( ak_tlv_context_get_uint32( asn1->current, &u32 ) == ak_error_ok )
           printf(" uint32 variable: %u (0x%x)\n", u32, u32 );
         ak_asn1_context_prev( asn1 );
      }

  ak_asn1_context_add_octet_string( asn1, buf, sizeof( buf ));

 /* формируем вложенный уровень */
  ak_asn1_context_create( asn_down_level = malloc( sizeof( struct asn1 )));
  ak_asn1_context_add_bool( asn_down_level, ak_false );
  for( i = 1; i < 9; i++ ) ak_asn1_context_add_octet_string( asn_down_level, buf, i );
  ak_asn1_context_add_asn1( asn1, TSEQUENCE, asn_down_level );
  ak_asn1_context_add_octet_string( asn1, buf, sizeof( buf ));
  ak_asn1_context_add_bool( asn1, ak_true );

 /* теперь мы формируем самый верхний уровень дерева */
  ak_asn1_context_create( &root );
  ak_asn1_context_add_asn1( &root, TSEQUENCE, asn1 );
  ak_asn1_context_add_octet_string( &root, "hello asnbuild", 15 );

 /* выводим сформированное дерево */
  fprintf( stdout, "\n" );
  ak_asn1_context_print( &root, stdout );

 /* уничтожаем дерево и выходим */
  ak_asn1_context_destroy( &root );
 return ak_libakrypt_destroy();
}