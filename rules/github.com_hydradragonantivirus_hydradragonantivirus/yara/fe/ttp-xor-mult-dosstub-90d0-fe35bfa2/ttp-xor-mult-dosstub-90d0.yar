rule TTP_XOR_MULT_DOSStub_90d0 {
  strings:
    $key_90d0 = { c4 b8 [2] b0 a0 [2] f7 a2 [2] b0 b3 [2] fe bf [2] f2 b5 [2] e5 be [2] fe f0 [2] c3 }

  condition:
    any of them
}