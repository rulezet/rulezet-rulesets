rule TTP_XOR_MULT_DOSStub_fc31 {
  strings:
    $key_fc31 = { a8 59 [2] dc 41 [2] 9b 43 [2] dc 52 [2] 92 5e [2] 9e 54 [2] 89 5f [2] 92 11 [2] af }

  condition:
    any of them
}