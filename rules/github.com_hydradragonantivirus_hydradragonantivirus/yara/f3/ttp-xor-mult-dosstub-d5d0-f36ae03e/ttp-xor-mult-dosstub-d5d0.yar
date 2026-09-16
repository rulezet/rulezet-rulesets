rule TTP_XOR_MULT_DOSStub_d5d0 {
  strings:
    $key_d5d0 = { 81 b8 [2] f5 a0 [2] b2 a2 [2] f5 b3 [2] bb bf [2] b7 b5 [2] a0 be [2] bb f0 [2] 86 }

  condition:
    any of them
}