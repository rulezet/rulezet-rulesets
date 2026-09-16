rule TTP_XOR_MULT_DOSStub_05be {
  strings:
    $key_05be = { 51 d6 [2] 25 ce [2] 62 cc [2] 25 dd [2] 6b d1 [2] 67 db [2] 70 d0 [2] 6b 9e [2] 56 }

  condition:
    any of them
}