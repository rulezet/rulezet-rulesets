rule TTP_XOR_MULT_DOSStub_e780 {
  strings:
    $key_e780 = { b3 e8 [2] c7 f0 [2] 80 f2 [2] c7 e3 [2] 89 ef [2] 85 e5 [2] 92 ee [2] 89 a0 [2] b4 }

  condition:
    any of them
}