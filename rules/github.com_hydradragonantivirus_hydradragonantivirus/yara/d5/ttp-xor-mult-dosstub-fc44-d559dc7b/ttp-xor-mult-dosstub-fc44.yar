rule TTP_XOR_MULT_DOSStub_fc44 {
  strings:
    $key_fc44 = { a8 2c [2] dc 34 [2] 9b 36 [2] dc 27 [2] 92 2b [2] 9e 21 [2] 89 2a [2] 92 64 [2] af }

  condition:
    any of them
}