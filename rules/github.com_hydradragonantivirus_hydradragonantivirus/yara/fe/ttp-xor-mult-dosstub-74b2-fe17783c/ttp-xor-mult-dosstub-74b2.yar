rule TTP_XOR_MULT_DOSStub_74b2 {
  strings:
    $key_74b2 = { 20 da [2] 54 c2 [2] 13 c0 [2] 54 d1 [2] 1a dd [2] 16 d7 [2] 01 dc [2] 1a 92 [2] 27 }

  condition:
    any of them
}