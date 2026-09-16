rule TTP_XOR_MULT_DOSStub_75b2 {
  strings:
    $key_75b2 = { 21 da [2] 55 c2 [2] 12 c0 [2] 55 d1 [2] 1b dd [2] 17 d7 [2] 00 dc [2] 1b 92 [2] 26 }

  condition:
    any of them
}