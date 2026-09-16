rule TTP_XOR_MULT_DOSStub_e7b2 {
  strings:
    $key_e7b2 = { b3 da [2] c7 c2 [2] 80 c0 [2] c7 d1 [2] 89 dd [2] 85 d7 [2] 92 dc [2] 89 92 [2] b4 }

  condition:
    any of them
}