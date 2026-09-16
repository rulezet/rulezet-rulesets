rule TTP_XOR_MULT_DOSStub_46b9 {
  strings:
    $key_46b9 = { 12 d1 [2] 66 c9 [2] 21 cb [2] 66 da [2] 28 d6 [2] 24 dc [2] 33 d7 [2] 28 99 [2] 15 }

  condition:
    any of them
}