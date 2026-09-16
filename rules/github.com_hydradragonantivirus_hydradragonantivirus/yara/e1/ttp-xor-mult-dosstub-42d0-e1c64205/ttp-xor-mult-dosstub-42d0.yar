rule TTP_XOR_MULT_DOSStub_42d0 {
  strings:
    $key_42d0 = { 16 b8 [2] 62 a0 [2] 25 a2 [2] 62 b3 [2] 2c bf [2] 20 b5 [2] 37 be [2] 2c f0 [2] 11 }

  condition:
    any of them
}