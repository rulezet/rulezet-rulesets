rule TTP_XOR_MULT_DOSStub_fc84 {
  strings:
    $key_fc84 = { a8 ec [2] dc f4 [2] 9b f6 [2] dc e7 [2] 92 eb [2] 9e e1 [2] 89 ea [2] 92 a4 [2] af }

  condition:
    any of them
}