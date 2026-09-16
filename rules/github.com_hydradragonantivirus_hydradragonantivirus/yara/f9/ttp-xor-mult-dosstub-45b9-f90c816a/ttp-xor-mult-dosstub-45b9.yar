rule TTP_XOR_MULT_DOSStub_45b9 {
  strings:
    $key_45b9 = { 11 d1 [2] 65 c9 [2] 22 cb [2] 65 da [2] 2b d6 [2] 27 dc [2] 30 d7 [2] 2b 99 [2] 16 }

  condition:
    any of them
}