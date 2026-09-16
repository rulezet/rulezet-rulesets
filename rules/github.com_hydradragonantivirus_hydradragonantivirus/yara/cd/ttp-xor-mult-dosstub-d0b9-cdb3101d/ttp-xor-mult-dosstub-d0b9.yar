rule TTP_XOR_MULT_DOSStub_d0b9 {
  strings:
    $key_d0b9 = { 84 d1 [2] f0 c9 [2] b7 cb [2] f0 da [2] be d6 [2] b2 dc [2] a5 d7 [2] be 99 [2] 83 }

  condition:
    any of them
}