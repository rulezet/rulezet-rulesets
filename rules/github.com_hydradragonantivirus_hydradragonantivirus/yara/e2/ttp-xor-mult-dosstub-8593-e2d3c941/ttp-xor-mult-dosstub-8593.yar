rule TTP_XOR_MULT_DOSStub_8593 {
  strings:
    $key_8593 = { d1 fb [2] a5 e3 [2] e2 e1 [2] a5 f0 [2] eb fc [2] e7 f6 [2] f0 fd [2] eb b3 [2] d6 }

  condition:
    any of them
}