rule TTP_XOR_MULT_DOSStub_fc42 {
  strings:
    $key_fc42 = { a8 2a [2] dc 32 [2] 9b 30 [2] dc 21 [2] 92 2d [2] 9e 27 [2] 89 2c [2] 92 62 [2] af }

  condition:
    any of them
}