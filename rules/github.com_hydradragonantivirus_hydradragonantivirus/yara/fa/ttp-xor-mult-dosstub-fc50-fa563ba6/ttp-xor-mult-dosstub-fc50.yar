rule TTP_XOR_MULT_DOSStub_fc50 {
  strings:
    $key_fc50 = { a8 38 [2] dc 20 [2] 9b 22 [2] dc 33 [2] 92 3f [2] 9e 35 [2] 89 3e [2] 92 70 [2] af }

  condition:
    any of them
}