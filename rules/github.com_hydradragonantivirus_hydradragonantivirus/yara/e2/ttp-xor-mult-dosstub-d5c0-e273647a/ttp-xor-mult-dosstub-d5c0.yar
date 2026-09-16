rule TTP_XOR_MULT_DOSStub_d5c0 {
  strings:
    $key_d5c0 = { 81 a8 [2] f5 b0 [2] b2 b2 [2] f5 a3 [2] bb af [2] b7 a5 [2] a0 ae [2] bb e0 [2] 86 }

  condition:
    any of them
}