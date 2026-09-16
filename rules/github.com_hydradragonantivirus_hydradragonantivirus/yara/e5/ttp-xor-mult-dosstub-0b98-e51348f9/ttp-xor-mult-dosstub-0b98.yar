rule TTP_XOR_MULT_DOSStub_0b98 {
  strings:
    $key_0b98 = { 5f f0 [2] 2b e8 [2] 6c ea [2] 2b fb [2] 65 f7 [2] 69 fd [2] 7e f6 [2] 65 b8 [2] 58 }

  condition:
    any of them
}