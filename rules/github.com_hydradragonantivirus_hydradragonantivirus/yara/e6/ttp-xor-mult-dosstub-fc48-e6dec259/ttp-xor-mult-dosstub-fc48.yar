rule TTP_XOR_MULT_DOSStub_fc48 {
  strings:
    $key_fc48 = { a8 20 [2] dc 38 [2] 9b 3a [2] dc 2b [2] 92 27 [2] 9e 2d [2] 89 26 [2] 92 68 [2] af }

  condition:
    any of them
}