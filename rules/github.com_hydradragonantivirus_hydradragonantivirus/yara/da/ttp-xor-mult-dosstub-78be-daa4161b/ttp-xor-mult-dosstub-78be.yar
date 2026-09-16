rule TTP_XOR_MULT_DOSStub_78be {
  strings:
    $key_78be = { 2c d6 [2] 58 ce [2] 1f cc [2] 58 dd [2] 16 d1 [2] 1a db [2] 0d d0 [2] 16 9e [2] 2b }

  condition:
    any of them
}