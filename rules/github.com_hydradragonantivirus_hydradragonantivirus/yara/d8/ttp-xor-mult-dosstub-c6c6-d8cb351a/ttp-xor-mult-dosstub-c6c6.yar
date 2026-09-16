rule TTP_XOR_MULT_DOSStub_c6c6 {
  strings:
    $key_c6c6 = { 92 ae [2] e6 b6 [2] a1 b4 [2] e6 a5 [2] a8 a9 [2] a4 a3 [2] b3 a8 [2] a8 e6 [2] 95 }

  condition:
    any of them
}