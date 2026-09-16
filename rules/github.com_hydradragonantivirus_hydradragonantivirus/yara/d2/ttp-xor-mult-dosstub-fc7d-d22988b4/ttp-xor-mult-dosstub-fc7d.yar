rule TTP_XOR_MULT_DOSStub_fc7d {
  strings:
    $key_fc7d = { a8 15 [2] dc 0d [2] 9b 0f [2] dc 1e [2] 92 12 [2] 9e 18 [2] 89 13 [2] 92 5d [2] af }

  condition:
    any of them
}