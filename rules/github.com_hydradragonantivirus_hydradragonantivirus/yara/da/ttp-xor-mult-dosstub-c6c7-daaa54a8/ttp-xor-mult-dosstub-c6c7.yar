rule TTP_XOR_MULT_DOSStub_c6c7 {
  strings:
    $key_c6c7 = { 92 af [2] e6 b7 [2] a1 b5 [2] e6 a4 [2] a8 a8 [2] a4 a2 [2] b3 a9 [2] a8 e7 [2] 95 }

  condition:
    any of them
}