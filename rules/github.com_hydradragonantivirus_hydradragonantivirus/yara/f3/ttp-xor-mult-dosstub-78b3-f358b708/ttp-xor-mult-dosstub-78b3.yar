rule TTP_XOR_MULT_DOSStub_78b3 {
  strings:
    $key_78b3 = { 2c db [2] 58 c3 [2] 1f c1 [2] 58 d0 [2] 16 dc [2] 1a d6 [2] 0d dd [2] 16 93 [2] 2b }

  condition:
    any of them
}