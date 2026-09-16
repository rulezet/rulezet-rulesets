rule TTP_XOR_MULT_DOSStub_80c5 {
  strings:
    $key_80c5 = { d4 ad [2] a0 b5 [2] e7 b7 [2] a0 a6 [2] ee aa [2] e2 a0 [2] f5 ab [2] ee e5 [2] d3 }

  condition:
    any of them
}