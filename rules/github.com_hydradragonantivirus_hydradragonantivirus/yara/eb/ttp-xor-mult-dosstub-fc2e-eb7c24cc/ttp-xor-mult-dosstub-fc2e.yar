rule TTP_XOR_MULT_DOSStub_fc2e {
  strings:
    $key_fc2e = { a8 46 [2] dc 5e [2] 9b 5c [2] dc 4d [2] 92 41 [2] 9e 4b [2] 89 40 [2] 92 0e [2] af }

  condition:
    any of them
}