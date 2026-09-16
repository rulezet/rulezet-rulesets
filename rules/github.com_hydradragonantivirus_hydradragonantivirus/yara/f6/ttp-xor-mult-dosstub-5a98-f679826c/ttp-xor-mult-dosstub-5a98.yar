rule TTP_XOR_MULT_DOSStub_5a98 {
  strings:
    $key_5a98 = { 0e f0 [2] 7a e8 [2] 3d ea [2] 7a fb [2] 34 f7 [2] 38 fd [2] 2f f6 [2] 34 b8 [2] 09 }

  condition:
    any of them
}