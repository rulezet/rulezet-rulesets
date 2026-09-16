rule TTP_XOR_MULT_DOSStub_e586 {
  strings:
    $key_e586 = { b1 ee [2] c5 f6 [2] 82 f4 [2] c5 e5 [2] 8b e9 [2] 87 e3 [2] 90 e8 [2] 8b a6 [2] b6 }

  condition:
    any of them
}