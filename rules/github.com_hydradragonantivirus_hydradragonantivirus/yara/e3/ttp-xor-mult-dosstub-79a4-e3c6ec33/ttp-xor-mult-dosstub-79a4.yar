rule TTP_XOR_MULT_DOSStub_79a4 {
  strings:
    $key_79a4 = { 2d cc [2] 59 d4 [2] 1e d6 [2] 59 c7 [2] 17 cb [2] 1b c1 [2] 0c ca [2] 17 84 [2] 2a }

  condition:
    any of them
}