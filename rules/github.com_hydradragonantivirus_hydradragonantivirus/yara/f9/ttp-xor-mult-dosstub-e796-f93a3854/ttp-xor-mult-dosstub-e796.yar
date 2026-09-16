rule TTP_XOR_MULT_DOSStub_e796 {
  strings:
    $key_e796 = { b3 fe [2] c7 e6 [2] 80 e4 [2] c7 f5 [2] 89 f9 [2] 85 f3 [2] 92 f8 [2] 89 b6 [2] b4 }

  condition:
    any of them
}