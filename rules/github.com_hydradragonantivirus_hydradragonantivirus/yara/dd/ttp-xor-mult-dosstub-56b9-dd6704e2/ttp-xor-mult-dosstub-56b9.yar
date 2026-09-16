rule TTP_XOR_MULT_DOSStub_56b9 {
  strings:
    $key_56b9 = { 02 d1 [2] 76 c9 [2] 31 cb [2] 76 da [2] 38 d6 [2] 34 dc [2] 23 d7 [2] 38 99 [2] 05 }

  condition:
    any of them
}