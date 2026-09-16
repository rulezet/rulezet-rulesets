rule TTP_XOR_MULT_DOSStub_04b9 {
  strings:
    $key_04b9 = { 50 d1 [2] 24 c9 [2] 63 cb [2] 24 da [2] 6a d6 [2] 66 dc [2] 71 d7 [2] 6a 99 [2] 57 }

  condition:
    any of them
}