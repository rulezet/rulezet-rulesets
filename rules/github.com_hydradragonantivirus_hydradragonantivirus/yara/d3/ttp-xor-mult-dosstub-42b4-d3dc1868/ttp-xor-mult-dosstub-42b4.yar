rule TTP_XOR_MULT_DOSStub_42b4 {
  strings:
    $key_42b4 = { 16 dc [2] 62 c4 [2] 25 c6 [2] 62 d7 [2] 2c db [2] 20 d1 [2] 37 da [2] 2c 94 [2] 11 }

  condition:
    any of them
}