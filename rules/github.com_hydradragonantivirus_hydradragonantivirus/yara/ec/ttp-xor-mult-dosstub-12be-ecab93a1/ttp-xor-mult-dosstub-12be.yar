rule TTP_XOR_MULT_DOSStub_12be {
  strings:
    $key_12be = { 46 d6 [2] 32 ce [2] 75 cc [2] 32 dd [2] 7c d1 [2] 70 db [2] 67 d0 [2] 7c 9e [2] 41 }

  condition:
    any of them
}