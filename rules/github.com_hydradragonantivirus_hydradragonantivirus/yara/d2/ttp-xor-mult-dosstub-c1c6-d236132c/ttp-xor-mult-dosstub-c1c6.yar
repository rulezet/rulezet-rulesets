rule TTP_XOR_MULT_DOSStub_c1c6 {
  strings:
    $key_c1c6 = { 95 ae [2] e1 b6 [2] a6 b4 [2] e1 a5 [2] af a9 [2] a3 a3 [2] b4 a8 [2] af e6 [2] 92 }

  condition:
    any of them
}