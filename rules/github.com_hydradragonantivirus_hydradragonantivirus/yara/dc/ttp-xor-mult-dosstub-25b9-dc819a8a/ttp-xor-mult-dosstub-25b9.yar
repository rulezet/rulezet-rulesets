rule TTP_XOR_MULT_DOSStub_25b9 {
  strings:
    $key_25b9 = { 71 d1 [2] 05 c9 [2] 42 cb [2] 05 da [2] 4b d6 [2] 47 dc [2] 50 d7 [2] 4b 99 [2] 76 }

  condition:
    any of them
}