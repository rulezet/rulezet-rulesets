rule TTP_XOR_MULT_DOSStub_42be {
  strings:
    $key_42be = { 16 d6 [2] 62 ce [2] 25 cc [2] 62 dd [2] 2c d1 [2] 20 db [2] 37 d0 [2] 2c 9e [2] 11 }

  condition:
    any of them
}