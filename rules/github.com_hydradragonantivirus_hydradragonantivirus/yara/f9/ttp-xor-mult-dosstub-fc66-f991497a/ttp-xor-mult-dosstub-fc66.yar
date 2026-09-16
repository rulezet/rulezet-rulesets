rule TTP_XOR_MULT_DOSStub_fc66 {
  strings:
    $key_fc66 = { a8 0e [2] dc 16 [2] 9b 14 [2] dc 05 [2] 92 09 [2] 9e 03 [2] 89 08 [2] 92 46 [2] af }

  condition:
    any of them
}