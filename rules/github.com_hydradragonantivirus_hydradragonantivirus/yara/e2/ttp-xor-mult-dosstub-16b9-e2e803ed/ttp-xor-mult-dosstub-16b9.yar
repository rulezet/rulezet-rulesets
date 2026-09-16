rule TTP_XOR_MULT_DOSStub_16b9 {
  strings:
    $key_16b9 = { 42 d1 [2] 36 c9 [2] 71 cb [2] 36 da [2] 78 d6 [2] 74 dc [2] 63 d7 [2] 78 99 [2] 45 }

  condition:
    any of them
}