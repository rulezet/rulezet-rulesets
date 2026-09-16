rule TTP_XOR_MULT_DOSStub_b098 {
  strings:
    $key_b098 = { e4 f0 [2] 90 e8 [2] d7 ea [2] 90 fb [2] de f7 [2] d2 fd [2] c5 f6 [2] de b8 [2] e3 }

  condition:
    any of them
}