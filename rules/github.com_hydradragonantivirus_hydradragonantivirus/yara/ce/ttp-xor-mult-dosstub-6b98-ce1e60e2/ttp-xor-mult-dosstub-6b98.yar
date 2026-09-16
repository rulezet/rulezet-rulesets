rule TTP_XOR_MULT_DOSStub_6b98 {
  strings:
    $key_6b98 = { 3f f0 [2] 4b e8 [2] 0c ea [2] 4b fb [2] 05 f7 [2] 09 fd [2] 1e f6 [2] 05 b8 [2] 38 }

  condition:
    any of them
}