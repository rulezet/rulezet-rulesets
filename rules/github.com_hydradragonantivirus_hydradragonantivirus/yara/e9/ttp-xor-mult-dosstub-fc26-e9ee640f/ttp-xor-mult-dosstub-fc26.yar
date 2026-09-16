rule TTP_XOR_MULT_DOSStub_fc26 {
  strings:
    $key_fc26 = { a8 4e [2] dc 56 [2] 9b 54 [2] dc 45 [2] 92 49 [2] 9e 43 [2] 89 48 [2] 92 06 [2] af }

  condition:
    any of them
}