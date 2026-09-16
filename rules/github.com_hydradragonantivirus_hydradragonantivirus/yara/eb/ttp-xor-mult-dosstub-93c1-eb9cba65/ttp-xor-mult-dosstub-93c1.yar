rule TTP_XOR_MULT_DOSStub_93c1 {
  strings:
    $key_93c1 = { c7 a9 [2] b3 b1 [2] f4 b3 [2] b3 a2 [2] fd ae [2] f1 a4 [2] e6 af [2] fd e1 [2] c0 }

  condition:
    any of them
}