rule TTP_XOR_MULT_DOSStub_d0b4 {
  strings:
    $key_d0b4 = { 84 dc [2] f0 c4 [2] b7 c6 [2] f0 d7 [2] be db [2] b2 d1 [2] a5 da [2] be 94 [2] 83 }

  condition:
    any of them
}