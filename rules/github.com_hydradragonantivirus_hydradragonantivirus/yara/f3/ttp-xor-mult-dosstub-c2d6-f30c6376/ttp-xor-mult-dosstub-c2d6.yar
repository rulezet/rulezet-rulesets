rule TTP_XOR_MULT_DOSStub_c2d6 {
  strings:
    $key_c2d6 = { 96 be [2] e2 a6 [2] a5 a4 [2] e2 b5 [2] ac b9 [2] a0 b3 [2] b7 b8 [2] ac f6 [2] 91 }

  condition:
    any of them
}