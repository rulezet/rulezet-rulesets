rule TTP_XOR_MULT_DOSStub_fc06 {
  strings:
    $key_fc06 = { a8 6e [2] dc 76 [2] 9b 74 [2] dc 65 [2] 92 69 [2] 9e 63 [2] 89 68 [2] 92 26 [2] af }

  condition:
    any of them
}