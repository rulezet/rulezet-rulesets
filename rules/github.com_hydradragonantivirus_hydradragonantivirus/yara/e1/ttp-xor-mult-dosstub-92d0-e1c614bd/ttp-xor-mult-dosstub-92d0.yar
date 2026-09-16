rule TTP_XOR_MULT_DOSStub_92d0 {
  strings:
    $key_92d0 = { c6 b8 [2] b2 a0 [2] f5 a2 [2] b2 b3 [2] fc bf [2] f0 b5 [2] e7 be [2] fc f0 [2] c1 }

  condition:
    any of them
}