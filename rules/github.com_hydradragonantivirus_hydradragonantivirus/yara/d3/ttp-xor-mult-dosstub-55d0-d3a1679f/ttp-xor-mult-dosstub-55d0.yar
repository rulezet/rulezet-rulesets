rule TTP_XOR_MULT_DOSStub_55d0 {
  strings:
    $key_55d0 = { 01 b8 [2] 75 a0 [2] 32 a2 [2] 75 b3 [2] 3b bf [2] 37 b5 [2] 20 be [2] 3b f0 [2] 06 }

  condition:
    any of them
}