rule TTP_XOR_MULT_DOSStub_10b9 {
  strings:
    $key_10b9 = { 44 d1 [2] 30 c9 [2] 77 cb [2] 30 da [2] 7e d6 [2] 72 dc [2] 65 d7 [2] 7e 99 [2] 43 }

  condition:
    any of them
}