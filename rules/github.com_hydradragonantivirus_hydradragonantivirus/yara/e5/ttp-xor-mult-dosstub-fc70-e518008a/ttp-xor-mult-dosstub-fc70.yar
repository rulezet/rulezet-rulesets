rule TTP_XOR_MULT_DOSStub_fc70 {
  strings:
    $key_fc70 = { a8 18 [2] dc 00 [2] 9b 02 [2] dc 13 [2] 92 1f [2] 9e 15 [2] 89 1e [2] 92 50 [2] af }

  condition:
    any of them
}