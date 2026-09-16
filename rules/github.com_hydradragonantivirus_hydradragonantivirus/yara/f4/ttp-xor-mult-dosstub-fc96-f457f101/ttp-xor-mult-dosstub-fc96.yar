rule TTP_XOR_MULT_DOSStub_fc96 {
  strings:
    $key_fc96 = { a8 fe [2] dc e6 [2] 9b e4 [2] dc f5 [2] 92 f9 [2] 9e f3 [2] 89 f8 [2] 92 b6 [2] af }

  condition:
    any of them
}