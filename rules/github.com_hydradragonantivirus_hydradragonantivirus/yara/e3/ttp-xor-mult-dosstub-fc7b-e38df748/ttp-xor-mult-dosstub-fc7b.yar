rule TTP_XOR_MULT_DOSStub_fc7b {
  strings:
    $key_fc7b = { a8 13 [2] dc 0b [2] 9b 09 [2] dc 18 [2] 92 14 [2] 9e 1e [2] 89 15 [2] 92 5b [2] af }

  condition:
    any of them
}