rule TTP_XOR_MULT_DOSStub_e7d6 {
  strings:
    $key_e7d6 = { b3 be [2] c7 a6 [2] 80 a4 [2] c7 b5 [2] 89 b9 [2] 85 b3 [2] 92 b8 [2] 89 f6 [2] b4 }

  condition:
    any of them
}