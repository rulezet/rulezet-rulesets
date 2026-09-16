rule TTP_XOR_MULT_DOSStub_17b2 {
  strings:
    $key_17b2 = { 43 da [2] 37 c2 [2] 70 c0 [2] 37 d1 [2] 79 dd [2] 75 d7 [2] 62 dc [2] 79 92 [2] 44 }

  condition:
    any of them
}