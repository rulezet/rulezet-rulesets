rule TTP_XOR_MULT_DOSStub_e086 {
  strings:
    $key_e086 = { b4 ee [2] c0 f6 [2] 87 f4 [2] c0 e5 [2] 8e e9 [2] 82 e3 [2] 95 e8 [2] 8e a6 [2] b3 }

  condition:
    any of them
}