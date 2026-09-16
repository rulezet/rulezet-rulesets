rule TTP_XOR_MULT_DOSStub_05b9 {
  strings:
    $key_05b9 = { 51 d1 [2] 25 c9 [2] 62 cb [2] 25 da [2] 6b d6 [2] 67 dc [2] 70 d7 [2] 6b 99 [2] 56 }

  condition:
    any of them
}