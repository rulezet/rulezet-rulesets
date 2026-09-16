rule TTP_XOR_MULT_DOSStub_d5a8 {
  strings:
    $key_d5a8 = { 81 c0 [2] f5 d8 [2] b2 da [2] f5 cb [2] bb c7 [2] b7 cd [2] a0 c6 [2] bb 88 [2] 86 }

  condition:
    any of them
}