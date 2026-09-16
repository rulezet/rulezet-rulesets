rule TTP_XOR_MULT_DOSStub_75be {
  strings:
    $key_75be = { 21 d6 [2] 55 ce [2] 12 cc [2] 55 dd [2] 1b d1 [2] 17 db [2] 00 d0 [2] 1b 9e [2] 26 }

  condition:
    any of them
}