rule TTP_XOR_MULT_DOSStub_97c3 {
  strings:
    $key_97c3 = { c3 ab [2] b7 b3 [2] f0 b1 [2] b7 a0 [2] f9 ac [2] f5 a6 [2] e2 ad [2] f9 e3 [2] c4 }

  condition:
    any of them
}