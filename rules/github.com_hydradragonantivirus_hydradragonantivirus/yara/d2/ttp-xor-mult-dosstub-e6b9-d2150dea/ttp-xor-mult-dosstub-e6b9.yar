rule TTP_XOR_MULT_DOSStub_e6b9 {
  strings:
    $key_e6b9 = { b2 d1 [2] c6 c9 [2] 81 cb [2] c6 da [2] 88 d6 [2] 84 dc [2] 93 d7 [2] 88 99 [2] b5 }

  condition:
    any of them
}