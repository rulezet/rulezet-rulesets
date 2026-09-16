rule TTP_XOR_MULT_DOSStub_4285 {
  strings:
    $key_4285 = { 16 ed [2] 62 f5 [2] 25 f7 [2] 62 e6 [2] 2c ea [2] 20 e0 [2] 37 eb [2] 2c a5 [2] 11 }

  condition:
    any of them
}