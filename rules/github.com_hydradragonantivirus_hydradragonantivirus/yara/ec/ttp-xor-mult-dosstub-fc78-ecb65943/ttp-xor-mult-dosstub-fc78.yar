rule TTP_XOR_MULT_DOSStub_fc78 {
  strings:
    $key_fc78 = { a8 10 [2] dc 08 [2] 9b 0a [2] dc 1b [2] 92 17 [2] 9e 1d [2] 89 16 [2] 92 58 [2] af }

  condition:
    any of them
}