rule TTP_XOR_MULT_DOSStub_32b9 {
  strings:
    $key_32b9 = { 66 d1 [2] 12 c9 [2] 55 cb [2] 12 da [2] 5c d6 [2] 50 dc [2] 47 d7 [2] 5c 99 [2] 61 }

  condition:
    any of them
}