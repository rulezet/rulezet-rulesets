rule TTP_XOR_MULT_DOSStub_fc46 {
  strings:
    $key_fc46 = { a8 2e [2] dc 36 [2] 9b 34 [2] dc 25 [2] 92 29 [2] 9e 23 [2] 89 28 [2] 92 66 [2] af }

  condition:
    any of them
}