rule TTP_XOR_MULT_DOSStub_4a98 {
  strings:
    $key_4a98 = { 1e f0 [2] 6a e8 [2] 2d ea [2] 6a fb [2] 24 f7 [2] 28 fd [2] 3f f6 [2] 24 b8 [2] 19 }

  condition:
    any of them
}