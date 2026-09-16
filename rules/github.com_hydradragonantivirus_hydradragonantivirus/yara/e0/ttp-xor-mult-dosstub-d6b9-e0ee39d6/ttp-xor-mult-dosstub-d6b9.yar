rule TTP_XOR_MULT_DOSStub_d6b9 {
  strings:
    $key_d6b9 = { 82 d1 [2] f6 c9 [2] b1 cb [2] f6 da [2] b8 d6 [2] b4 dc [2] a3 d7 [2] b8 99 [2] 85 }

  condition:
    any of them
}