rule TTP_XOR_MULT_DOSStub_79be {
  strings:
    $key_79be = { 2d d6 [2] 59 ce [2] 1e cc [2] 59 dd [2] 17 d1 [2] 1b db [2] 0c d0 [2] 17 9e [2] 2a }

  condition:
    any of them
}