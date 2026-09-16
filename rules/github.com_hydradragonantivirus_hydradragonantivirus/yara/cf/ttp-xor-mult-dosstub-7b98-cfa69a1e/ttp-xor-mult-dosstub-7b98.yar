rule TTP_XOR_MULT_DOSStub_7b98 {
  strings:
    $key_7b98 = { 2f f0 [2] 5b e8 [2] 1c ea [2] 5b fb [2] 15 f7 [2] 19 fd [2] 0e f6 [2] 15 b8 [2] 28 }

  condition:
    any of them
}