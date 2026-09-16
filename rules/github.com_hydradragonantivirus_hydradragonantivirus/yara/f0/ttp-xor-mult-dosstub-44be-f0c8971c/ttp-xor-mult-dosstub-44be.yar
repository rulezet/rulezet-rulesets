rule TTP_XOR_MULT_DOSStub_44be {
  strings:
    $key_44be = { 10 d6 [2] 64 ce [2] 23 cc [2] 64 dd [2] 2a d1 [2] 26 db [2] 31 d0 [2] 2a 9e [2] 17 }

  condition:
    any of them
}