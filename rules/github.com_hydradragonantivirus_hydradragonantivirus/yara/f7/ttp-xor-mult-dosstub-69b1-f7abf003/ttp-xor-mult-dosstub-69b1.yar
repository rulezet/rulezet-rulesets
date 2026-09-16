rule TTP_XOR_MULT_DOSStub_69b1 {
  strings:
    $key_69b1 = { 3d d9 [2] 49 c1 [2] 0e c3 [2] 49 d2 [2] 07 de [2] 0b d4 [2] 1c df [2] 07 91 [2] 3a }

  condition:
    any of them
}