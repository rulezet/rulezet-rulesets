rule TTP_XOR_MULT_DOSStub_7186 {
  strings:
    $key_7186 = { 25 ee [2] 51 f6 [2] 16 f4 [2] 51 e5 [2] 1f e9 [2] 13 e3 [2] 04 e8 [2] 1f a6 [2] 22 }

  condition:
    any of them
}