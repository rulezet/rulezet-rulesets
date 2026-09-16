rule TTP_XOR_MULT_DOSStub_c686 {
  strings:
    $key_c686 = { 92 ee [2] e6 f6 [2] a1 f4 [2] e6 e5 [2] a8 e9 [2] a4 e3 [2] b3 e8 [2] a8 a6 [2] 95 }

  condition:
    any of them
}