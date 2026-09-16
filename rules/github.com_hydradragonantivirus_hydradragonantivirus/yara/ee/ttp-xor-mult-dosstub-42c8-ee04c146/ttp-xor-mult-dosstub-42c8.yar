rule TTP_XOR_MULT_DOSStub_42c8 {
  strings:
    $key_42c8 = { 16 a0 [2] 62 b8 [2] 25 ba [2] 62 ab [2] 2c a7 [2] 20 ad [2] 37 a6 [2] 2c e8 [2] 11 }

  condition:
    any of them
}