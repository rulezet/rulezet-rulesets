rule TTP_XOR_MULT_DOSStub_c6d9 {
  strings:
    $key_c6d9 = { 92 b1 [2] e6 a9 [2] a1 ab [2] e6 ba [2] a8 b6 [2] a4 bc [2] b3 b7 [2] a8 f9 [2] 95 }

  condition:
    any of them
}