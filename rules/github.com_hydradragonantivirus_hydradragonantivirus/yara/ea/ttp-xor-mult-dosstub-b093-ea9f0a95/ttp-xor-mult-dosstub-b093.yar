rule TTP_XOR_MULT_DOSStub_b093 {
  strings:
    $key_b093 = { e4 fb [2] 90 e3 [2] d7 e1 [2] 90 f0 [2] de fc [2] d2 f6 [2] c5 fd [2] de b3 [2] e3 }

  condition:
    any of them
}