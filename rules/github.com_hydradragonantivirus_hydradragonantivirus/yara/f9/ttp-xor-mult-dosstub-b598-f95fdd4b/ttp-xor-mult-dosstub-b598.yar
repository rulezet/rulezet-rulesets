rule TTP_XOR_MULT_DOSStub_b598 {
  strings:
    $key_b598 = { e1 f0 [2] 95 e8 [2] d2 ea [2] 95 fb [2] db f7 [2] d7 fd [2] c0 f6 [2] db b8 [2] e6 }

  condition:
    any of them
}