rule TTP_XOR_MULT_DOSStub_69be {
  strings:
    $key_69be = { 3d d6 [2] 49 ce [2] 0e cc [2] 49 dd [2] 07 d1 [2] 0b db [2] 1c d0 [2] 07 9e [2] 3a }

  condition:
    any of them
}