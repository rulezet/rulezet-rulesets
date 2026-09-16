rule TTP_XOR_MULT_DOSStub_39be {
  strings:
    $key_39be = { 6d d6 [2] 19 ce [2] 5e cc [2] 19 dd [2] 57 d1 [2] 5b db [2] 4c d0 [2] 57 9e [2] 6a }

  condition:
    any of them
}