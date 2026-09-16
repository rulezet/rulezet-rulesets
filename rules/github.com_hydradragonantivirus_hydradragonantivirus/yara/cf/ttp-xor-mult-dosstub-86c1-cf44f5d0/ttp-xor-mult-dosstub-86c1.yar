rule TTP_XOR_MULT_DOSStub_86c1 {
  strings:
    $key_86c1 = { d2 a9 [2] a6 b1 [2] e1 b3 [2] a6 a2 [2] e8 ae [2] e4 a4 [2] f3 af [2] e8 e1 [2] d5 }

  condition:
    any of them
}