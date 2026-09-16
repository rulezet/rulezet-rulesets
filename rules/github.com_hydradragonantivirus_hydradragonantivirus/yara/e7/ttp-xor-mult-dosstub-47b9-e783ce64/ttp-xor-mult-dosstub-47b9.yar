rule TTP_XOR_MULT_DOSStub_47b9 {
  strings:
    $key_47b9 = { 13 d1 [2] 67 c9 [2] 20 cb [2] 67 da [2] 29 d6 [2] 25 dc [2] 32 d7 [2] 29 99 [2] 14 }

  condition:
    any of them
}