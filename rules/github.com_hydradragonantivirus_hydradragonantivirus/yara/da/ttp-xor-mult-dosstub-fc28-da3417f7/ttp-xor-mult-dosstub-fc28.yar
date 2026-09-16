rule TTP_XOR_MULT_DOSStub_fc28 {
  strings:
    $key_fc28 = { a8 40 [2] dc 58 [2] 9b 5a [2] dc 4b [2] 92 47 [2] 9e 4d [2] 89 46 [2] 92 08 [2] af }

  condition:
    any of them
}