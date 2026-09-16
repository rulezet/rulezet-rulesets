rule TTP_XOR_MULT_DOSStub_90d1 {
  strings:
    $key_90d1 = { c4 b9 [2] b0 a1 [2] f7 a3 [2] b0 b2 [2] fe be [2] f2 b4 [2] e5 bf [2] fe f1 [2] c3 }

  condition:
    any of them
}