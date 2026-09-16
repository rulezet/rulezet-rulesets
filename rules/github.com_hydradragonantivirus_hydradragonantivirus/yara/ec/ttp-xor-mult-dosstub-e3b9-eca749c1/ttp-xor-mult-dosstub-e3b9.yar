rule TTP_XOR_MULT_DOSStub_e3b9 {
  strings:
    $key_e3b9 = { b7 d1 [2] c3 c9 [2] 84 cb [2] c3 da [2] 8d d6 [2] 81 dc [2] 96 d7 [2] 8d 99 [2] b0 }

  condition:
    any of them
}