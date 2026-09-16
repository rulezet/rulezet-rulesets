rule TTP_XOR_MULT_DOSStub_80c3 {
  strings:
    $key_80c3 = { d4 ab [2] a0 b3 [2] e7 b1 [2] a0 a0 [2] ee ac [2] e2 a6 [2] f5 ad [2] ee e3 [2] d3 }

  condition:
    any of them
}