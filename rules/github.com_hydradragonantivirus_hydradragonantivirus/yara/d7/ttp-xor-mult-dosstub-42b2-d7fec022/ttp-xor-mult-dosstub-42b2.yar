rule TTP_XOR_MULT_DOSStub_42b2 {
  strings:
    $key_42b2 = { 16 da [2] 62 c2 [2] 25 c0 [2] 62 d1 [2] 2c dd [2] 20 d7 [2] 37 dc [2] 2c 92 [2] 11 }

  condition:
    any of them
}