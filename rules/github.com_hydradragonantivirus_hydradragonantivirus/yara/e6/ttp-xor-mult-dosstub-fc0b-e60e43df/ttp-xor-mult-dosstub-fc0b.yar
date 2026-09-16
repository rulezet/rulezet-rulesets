rule TTP_XOR_MULT_DOSStub_fc0b {
  strings:
    $key_fc0b = { a8 63 [2] dc 7b [2] 9b 79 [2] dc 68 [2] 92 64 [2] 9e 6e [2] 89 65 [2] 92 2b [2] af }

  condition:
    any of them
}