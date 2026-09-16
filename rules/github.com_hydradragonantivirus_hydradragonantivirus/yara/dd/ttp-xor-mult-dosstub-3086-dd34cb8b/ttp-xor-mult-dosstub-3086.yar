rule TTP_XOR_MULT_DOSStub_3086 {
  strings:
    $key_3086 = { 64 ee [2] 10 f6 [2] 57 f4 [2] 10 e5 [2] 5e e9 [2] 52 e3 [2] 45 e8 [2] 5e a6 [2] 63 }

  condition:
    any of them
}