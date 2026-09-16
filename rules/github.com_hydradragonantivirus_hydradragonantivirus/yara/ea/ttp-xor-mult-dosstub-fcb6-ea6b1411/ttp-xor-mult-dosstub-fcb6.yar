rule TTP_XOR_MULT_DOSStub_fcb6 {
  strings:
    $key_fcb6 = { a8 de [2] dc c6 [2] 9b c4 [2] dc d5 [2] 92 d9 [2] 9e d3 [2] 89 d8 [2] 92 96 [2] af }

  condition:
    any of them
}