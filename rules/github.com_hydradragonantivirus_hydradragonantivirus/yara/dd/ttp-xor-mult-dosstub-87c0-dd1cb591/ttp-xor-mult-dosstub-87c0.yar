rule TTP_XOR_MULT_DOSStub_87c0 {
  strings:
    $key_87c0 = { d3 a8 [2] a7 b0 [2] e0 b2 [2] a7 a3 [2] e9 af [2] e5 a5 [2] f2 ae [2] e9 e0 [2] d4 }

  condition:
    any of them
}