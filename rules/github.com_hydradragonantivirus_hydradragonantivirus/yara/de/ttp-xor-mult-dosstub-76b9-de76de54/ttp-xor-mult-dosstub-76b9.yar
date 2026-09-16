rule TTP_XOR_MULT_DOSStub_76b9 {
  strings:
    $key_76b9 = { 22 d1 [2] 56 c9 [2] 11 cb [2] 56 da [2] 18 d6 [2] 14 dc [2] 03 d7 [2] 18 99 [2] 25 }

  condition:
    any of them
}