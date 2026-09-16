rule TTP_XOR_MULT_DOSStub_55b4 {
  strings:
    $key_55b4 = { 01 dc [2] 75 c4 [2] 32 c6 [2] 75 d7 [2] 3b db [2] 37 d1 [2] 20 da [2] 3b 94 [2] 06 }

  condition:
    any of them
}