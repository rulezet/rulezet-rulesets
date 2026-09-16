rule TTP_XOR_MULT_DOSStub_7d98 {
  strings:
    $key_7d98 = { 29 f0 [2] 5d e8 [2] 1a ea [2] 5d fb [2] 13 f7 [2] 1f fd [2] 08 f6 [2] 13 b8 [2] 2e }

  condition:
    any of them
}