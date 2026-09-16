rule TTP_XOR_MULT_DOSStub_03b4 {
  strings:
    $key_03b4 = { 57 dc [2] 23 c4 [2] 64 c6 [2] 23 d7 [2] 6d db [2] 61 d1 [2] 76 da [2] 6d 94 [2] 50 }

  condition:
    any of them
}