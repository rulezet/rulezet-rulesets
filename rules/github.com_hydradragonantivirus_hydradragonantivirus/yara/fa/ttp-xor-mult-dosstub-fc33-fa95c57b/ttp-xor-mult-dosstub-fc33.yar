rule TTP_XOR_MULT_DOSStub_fc33 {
  strings:
    $key_fc33 = { a8 5b [2] dc 43 [2] 9b 41 [2] dc 50 [2] 92 5c [2] 9e 56 [2] 89 5d [2] 92 13 [2] af }

  condition:
    any of them
}