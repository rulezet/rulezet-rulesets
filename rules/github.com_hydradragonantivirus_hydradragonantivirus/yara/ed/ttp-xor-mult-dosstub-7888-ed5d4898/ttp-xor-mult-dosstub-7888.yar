rule TTP_XOR_MULT_DOSStub_7888 {
  strings:
    $key_7888 = { 2c e0 [2] 58 f8 [2] 1f fa [2] 58 eb [2] 16 e7 [2] 1a ed [2] 0d e6 [2] 16 a8 [2] 2b }

  condition:
    any of them
}