rule TTP_XOR_MULT_DOSStub_85c0 {
  strings:
    $key_85c0 = { d1 a8 [2] a5 b0 [2] e2 b2 [2] a5 a3 [2] eb af [2] e7 a5 [2] f0 ae [2] eb e0 [2] d6 }

  condition:
    any of them
}