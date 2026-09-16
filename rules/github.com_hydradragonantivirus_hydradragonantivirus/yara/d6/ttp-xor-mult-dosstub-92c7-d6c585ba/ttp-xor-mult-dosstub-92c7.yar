rule TTP_XOR_MULT_DOSStub_92c7 {
  strings:
    $key_92c7 = { c6 af [2] b2 b7 [2] f5 b5 [2] b2 a4 [2] fc a8 [2] f0 a2 [2] e7 a9 [2] fc e7 [2] c1 }

  condition:
    any of them
}