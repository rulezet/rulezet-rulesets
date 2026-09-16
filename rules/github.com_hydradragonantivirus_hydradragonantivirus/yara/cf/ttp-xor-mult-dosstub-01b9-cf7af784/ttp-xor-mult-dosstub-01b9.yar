rule TTP_XOR_MULT_DOSStub_01b9 {
  strings:
    $key_01b9 = { 55 d1 [2] 21 c9 [2] 66 cb [2] 21 da [2] 6f d6 [2] 63 dc [2] 74 d7 [2] 6f 99 [2] 52 }

  condition:
    any of them
}