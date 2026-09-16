rule TTP_XOR_MULT_DOSStub_91c1 {
  strings:
    $key_91c1 = { c5 a9 [2] b1 b1 [2] f6 b3 [2] b1 a2 [2] ff ae [2] f3 a4 [2] e4 af [2] ff e1 [2] c2 }

  condition:
    any of them
}