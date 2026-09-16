rule TTP_XOR_MULT_DOSStub_d7c8 {
  strings:
    $key_d7c8 = { 83 a0 [2] f7 b8 [2] b0 ba [2] f7 ab [2] b9 a7 [2] b5 ad [2] a2 a6 [2] b9 e8 [2] 84 }

  condition:
    any of them
}