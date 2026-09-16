rule TTP_XOR_MULT_DOSStub_d5d6 {
  strings:
    $key_d5d6 = { 81 be [2] f5 a6 [2] b2 a4 [2] f5 b5 [2] bb b9 [2] b7 b3 [2] a0 b8 [2] bb f6 [2] 86 }

  condition:
    any of them
}