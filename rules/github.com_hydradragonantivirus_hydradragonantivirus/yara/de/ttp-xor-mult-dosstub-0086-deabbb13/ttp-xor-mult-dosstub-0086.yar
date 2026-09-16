rule TTP_XOR_MULT_DOSStub_0086 {
  strings:
    $key_0086 = { 54 ee [2] 20 f6 [2] 67 f4 [2] 20 e5 [2] 6e e9 [2] 62 e3 [2] 75 e8 [2] 6e a6 [2] 53 }

  condition:
    any of them
}