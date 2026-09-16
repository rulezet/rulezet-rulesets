rule TTP_XOR_MULT_DOSStub_90c0 {
  strings:
    $key_90c0 = { c4 a8 [2] b0 b0 [2] f7 b2 [2] b0 a3 [2] fe af [2] f2 a5 [2] e5 ae [2] fe e0 [2] c3 }

  condition:
    any of them
}