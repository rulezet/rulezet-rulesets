rule TTP_XOR_MULT_DOSStub_058b {
  strings:
    $key_058b = { 51 e3 [2] 25 fb [2] 62 f9 [2] 25 e8 [2] 6b e4 [2] 67 ee [2] 70 e5 [2] 6b ab [2] 56 }

  condition:
    any of them
}