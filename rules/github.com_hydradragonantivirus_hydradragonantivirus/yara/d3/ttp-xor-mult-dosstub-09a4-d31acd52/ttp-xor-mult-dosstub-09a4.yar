rule TTP_XOR_MULT_DOSStub_09a4 {
  strings:
    $key_09a4 = { 5d cc [2] 29 d4 [2] 6e d6 [2] 29 c7 [2] 67 cb [2] 6b c1 [2] 7c ca [2] 67 84 [2] 5a }

  condition:
    any of them
}