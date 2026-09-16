rule TTP_XOR_MULT_DOSStub_04b4 {
  strings:
    $key_04b4 = { 50 dc [2] 24 c4 [2] 63 c6 [2] 24 d7 [2] 6a db [2] 66 d1 [2] 71 da [2] 6a 94 [2] 57 }

  condition:
    any of them
}