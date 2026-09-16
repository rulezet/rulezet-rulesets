rule TTP_XOR_MULT_DOSStub_fc05 {
  strings:
    $key_fc05 = { a8 6d [2] dc 75 [2] 9b 77 [2] dc 66 [2] 92 6a [2] 9e 60 [2] 89 6b [2] 92 25 [2] af }

  condition:
    any of them
}