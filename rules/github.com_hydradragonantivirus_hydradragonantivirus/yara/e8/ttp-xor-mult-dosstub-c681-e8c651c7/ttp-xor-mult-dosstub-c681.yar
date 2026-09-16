rule TTP_XOR_MULT_DOSStub_c681 {
  strings:
    $key_c681 = { 92 e9 [2] e6 f1 [2] a1 f3 [2] e6 e2 [2] a8 ee [2] a4 e4 [2] b3 ef [2] a8 a1 [2] 95 }

  condition:
    any of them
}