rule TTP_XOR_MULT_DOSStub_fc09 {
  strings:
    $key_fc09 = { a8 61 [2] dc 79 [2] 9b 7b [2] dc 6a [2] 92 66 [2] 9e 6c [2] 89 67 [2] 92 29 [2] af }

  condition:
    any of them
}