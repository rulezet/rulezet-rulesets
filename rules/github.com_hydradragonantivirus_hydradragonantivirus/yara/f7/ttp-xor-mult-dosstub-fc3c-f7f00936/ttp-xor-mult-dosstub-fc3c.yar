rule TTP_XOR_MULT_DOSStub_fc3c {
  strings:
    $key_fc3c = { a8 54 [2] dc 4c [2] 9b 4e [2] dc 5f [2] 92 53 [2] 9e 59 [2] 89 52 [2] 92 1c [2] af }

  condition:
    any of them
}