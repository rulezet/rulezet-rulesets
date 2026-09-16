rule TTP_XOR_MULT_DOSStub_d4c8 {
  strings:
    $key_d4c8 = { 80 a0 [2] f4 b8 [2] b3 ba [2] f4 ab [2] ba a7 [2] b6 ad [2] a1 a6 [2] ba e8 [2] 87 }

  condition:
    any of them
}