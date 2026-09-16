rule TTP_XOR_MULT_DOSStub_fce6 {
  strings:
    $key_fce6 = { a8 8e [2] dc 96 [2] 9b 94 [2] dc 85 [2] 92 89 [2] 9e 83 [2] 89 88 [2] 92 c6 [2] af }

  condition:
    any of them
}