rule TTP_XOR_MULT_DOSStub_27b2 {
  strings:
    $key_27b2 = { 73 da [2] 07 c2 [2] 40 c0 [2] 07 d1 [2] 49 dd [2] 45 d7 [2] 52 dc [2] 49 92 [2] 74 }

  condition:
    any of them
}