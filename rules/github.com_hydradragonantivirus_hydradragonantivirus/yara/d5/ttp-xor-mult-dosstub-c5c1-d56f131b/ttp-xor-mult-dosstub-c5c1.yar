rule TTP_XOR_MULT_DOSStub_c5c1 {
  strings:
    $key_c5c1 = { 91 a9 [2] e5 b1 [2] a2 b3 [2] e5 a2 [2] ab ae [2] a7 a4 [2] b0 af [2] ab e1 [2] 96 }

  condition:
    any of them
}