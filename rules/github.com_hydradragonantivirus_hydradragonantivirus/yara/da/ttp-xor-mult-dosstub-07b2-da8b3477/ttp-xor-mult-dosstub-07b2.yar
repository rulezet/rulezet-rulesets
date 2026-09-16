rule TTP_XOR_MULT_DOSStub_07b2 {
  strings:
    $key_07b2 = { 53 da [2] 27 c2 [2] 60 c0 [2] 27 d1 [2] 69 dd [2] 65 d7 [2] 72 dc [2] 69 92 [2] 54 }

  condition:
    any of them
}