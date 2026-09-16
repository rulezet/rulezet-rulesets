rule TTP_XOR_MULT_DOSStub_b095 {
  strings:
    $key_b095 = { e4 fd [2] 90 e5 [2] d7 e7 [2] 90 f6 [2] de fa [2] d2 f0 [2] c5 fb [2] de b5 [2] e3 }

  condition:
    any of them
}