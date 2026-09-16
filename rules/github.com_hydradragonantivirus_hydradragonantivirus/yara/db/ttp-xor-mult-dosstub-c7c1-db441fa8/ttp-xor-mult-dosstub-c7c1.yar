rule TTP_XOR_MULT_DOSStub_c7c1 {
  strings:
    $key_c7c1 = { 93 a9 [2] e7 b1 [2] a0 b3 [2] e7 a2 [2] a9 ae [2] a5 a4 [2] b2 af [2] a9 e1 [2] 94 }

  condition:
    any of them
}