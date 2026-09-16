rule TTP_XOR_MULT_DOSStub_c1c1 {
  strings:
    $key_c1c1 = { 95 a9 [2] e1 b1 [2] a6 b3 [2] e1 a2 [2] af ae [2] a3 a4 [2] b4 af [2] af e1 [2] 92 }

  condition:
    any of them
}