rule TTP_XOR_MULT_DOSStub_27b4 {
  strings:
    $key_27b4 = { 73 dc [2] 07 c4 [2] 40 c6 [2] 07 d7 [2] 49 db [2] 45 d1 [2] 52 da [2] 49 94 [2] 74 }

  condition:
    any of them
}