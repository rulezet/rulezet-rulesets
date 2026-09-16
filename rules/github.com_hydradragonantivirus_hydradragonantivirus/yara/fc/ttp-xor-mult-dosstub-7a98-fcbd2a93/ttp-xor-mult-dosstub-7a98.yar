rule TTP_XOR_MULT_DOSStub_7a98 {
  strings:
    $key_7a98 = { 2e f0 [2] 5a e8 [2] 1d ea [2] 5a fb [2] 14 f7 [2] 18 fd [2] 0f f6 [2] 14 b8 [2] 29 }

  condition:
    any of them
}