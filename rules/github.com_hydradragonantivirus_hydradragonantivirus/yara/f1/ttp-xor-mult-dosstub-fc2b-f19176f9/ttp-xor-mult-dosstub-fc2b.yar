rule TTP_XOR_MULT_DOSStub_fc2b {
  strings:
    $key_fc2b = { a8 43 [2] dc 5b [2] 9b 59 [2] dc 48 [2] 92 44 [2] 9e 4e [2] 89 45 [2] 92 0b [2] af }

  condition:
    any of them
}