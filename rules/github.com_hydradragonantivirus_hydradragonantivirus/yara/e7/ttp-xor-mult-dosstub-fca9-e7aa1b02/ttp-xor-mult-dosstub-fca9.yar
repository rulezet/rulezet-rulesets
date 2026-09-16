rule TTP_XOR_MULT_DOSStub_fca9 {
  strings:
    $key_fca9 = { a8 c1 [2] dc d9 [2] 9b db [2] dc ca [2] 92 c6 [2] 9e cc [2] 89 c7 [2] 92 89 [2] af }

  condition:
    any of them
}