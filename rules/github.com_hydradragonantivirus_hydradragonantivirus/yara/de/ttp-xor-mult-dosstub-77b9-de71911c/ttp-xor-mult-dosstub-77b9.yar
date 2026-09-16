rule TTP_XOR_MULT_DOSStub_77b9 {
  strings:
    $key_77b9 = { 23 d1 [2] 57 c9 [2] 10 cb [2] 57 da [2] 19 d6 [2] 15 dc [2] 02 d7 [2] 19 99 [2] 24 }

  condition:
    any of them
}