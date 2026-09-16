rule TTP_XOR_MULT_DOSStub_36b2 {
  strings:
    $key_36b2 = { 62 da [2] 16 c2 [2] 51 c0 [2] 16 d1 [2] 58 dd [2] 54 d7 [2] 43 dc [2] 58 92 [2] 65 }

  condition:
    any of them
}