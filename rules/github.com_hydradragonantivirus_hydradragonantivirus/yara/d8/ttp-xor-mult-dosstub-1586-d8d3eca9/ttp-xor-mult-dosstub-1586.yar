rule TTP_XOR_MULT_DOSStub_1586 {
  strings:
    $key_1586 = { 41 ee [2] 35 f6 [2] 72 f4 [2] 35 e5 [2] 7b e9 [2] 77 e3 [2] 60 e8 [2] 7b a6 [2] 46 }

  condition:
    any of them
}