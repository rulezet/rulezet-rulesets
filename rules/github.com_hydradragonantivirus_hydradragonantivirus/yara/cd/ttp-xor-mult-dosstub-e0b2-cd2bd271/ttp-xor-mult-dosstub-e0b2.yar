rule TTP_XOR_MULT_DOSStub_e0b2 {
  strings:
    $key_e0b2 = { b4 da [2] c0 c2 [2] 87 c0 [2] c0 d1 [2] 8e dd [2] 82 d7 [2] 95 dc [2] 8e 92 [2] b3 }

  condition:
    any of them
}