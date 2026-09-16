rule psymodel_table2__flt32___32_big_40_ {
  strings:
    $a0 = { 3f e3 9e 89 3f ec 53 e5 3f f5 5e a7 3f f9 14 9b 3f fc d9 0e 3f ea 8f 7b 3f d9 97 da 3f bf 84 e2 3f a8 91 7c 3f 80 00 00 }

  condition:
    $a0
}