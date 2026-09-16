rule TTP_XOR_MULT_DOSStub_fcb1 {
  strings:
    $key_fcb1 = { a8 d9 [2] dc c1 [2] 9b c3 [2] dc d2 [2] 92 de [2] 9e d4 [2] 89 df [2] 92 91 [2] af }

  condition:
    any of them
}