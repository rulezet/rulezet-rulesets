rule TTP_XOR_MULT_DOSStub_fc68 {
  strings:
    $key_fc68 = { a8 00 [2] dc 18 [2] 9b 1a [2] dc 0b [2] 92 07 [2] 9e 0d [2] 89 06 [2] 92 48 [2] af }

  condition:
    any of them
}