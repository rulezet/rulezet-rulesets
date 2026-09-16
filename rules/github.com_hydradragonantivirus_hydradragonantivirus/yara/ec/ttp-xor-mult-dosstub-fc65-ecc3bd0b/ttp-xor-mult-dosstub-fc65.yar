rule TTP_XOR_MULT_DOSStub_fc65 {
  strings:
    $key_fc65 = { a8 0d [2] dc 15 [2] 9b 17 [2] dc 06 [2] 92 0a [2] 9e 00 [2] 89 0b [2] 92 45 [2] af }

  condition:
    any of them
}