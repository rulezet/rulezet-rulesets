rule TTP_XOR_MULT_DOSStub_fc30 {
  strings:
    $key_fc30 = { a8 58 [2] dc 40 [2] 9b 42 [2] dc 53 [2] 92 5f [2] 9e 55 [2] 89 5e [2] 92 10 [2] af }

  condition:
    any of them
}