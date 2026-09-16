rule TTP_XOR_MULT_DOSStub_56b2 {
  strings:
    $key_56b2 = { 02 da [2] 76 c2 [2] 31 c0 [2] 76 d1 [2] 38 dd [2] 34 d7 [2] 23 dc [2] 38 92 [2] 05 }

  condition:
    any of them
}