rule TTP_XOR_MULT_DOSStub_38be {
  strings:
    $key_38be = { 6c d6 [2] 18 ce [2] 5f cc [2] 18 dd [2] 56 d1 [2] 5a db [2] 4d d0 [2] 56 9e [2] 6b }

  condition:
    any of them
}