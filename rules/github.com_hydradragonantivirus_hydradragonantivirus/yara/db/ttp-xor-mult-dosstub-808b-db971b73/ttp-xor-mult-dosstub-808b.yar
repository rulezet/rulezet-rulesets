rule TTP_XOR_MULT_DOSStub_808b {
  strings:
    $key_808b = { d4 e3 [2] a0 fb [2] e7 f9 [2] a0 e8 [2] ee e4 [2] e2 ee [2] f5 e5 [2] ee ab [2] d3 }

  condition:
    any of them
}