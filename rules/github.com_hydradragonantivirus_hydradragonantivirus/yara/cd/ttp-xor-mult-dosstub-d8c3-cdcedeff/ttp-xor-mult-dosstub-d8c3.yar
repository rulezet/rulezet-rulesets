rule TTP_XOR_MULT_DOSStub_d8c3 {
  strings:
    $key_d8c3 = { 8c ab [2] f8 b3 [2] bf b1 [2] f8 a0 [2] b6 ac [2] ba a6 [2] ad ad [2] b6 e3 [2] 8b }

  condition:
    any of them
}