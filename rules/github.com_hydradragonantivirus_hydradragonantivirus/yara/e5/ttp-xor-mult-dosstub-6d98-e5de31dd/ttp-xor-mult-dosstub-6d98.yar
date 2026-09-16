rule TTP_XOR_MULT_DOSStub_6d98 {
  strings:
    $key_6d98 = { 39 f0 [2] 4d e8 [2] 0a ea [2] 4d fb [2] 03 f7 [2] 0f fd [2] 18 f6 [2] 03 b8 [2] 3e }

  condition:
    any of them
}