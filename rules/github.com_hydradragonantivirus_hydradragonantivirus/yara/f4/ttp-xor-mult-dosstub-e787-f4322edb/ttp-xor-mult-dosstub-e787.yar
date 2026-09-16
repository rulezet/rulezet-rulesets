rule TTP_XOR_MULT_DOSStub_e787 {
  strings:
    $key_e787 = { b3 ef [2] c7 f7 [2] 80 f5 [2] c7 e4 [2] 89 e8 [2] 85 e2 [2] 92 e9 [2] 89 a7 [2] b4 }

  condition:
    any of them
}