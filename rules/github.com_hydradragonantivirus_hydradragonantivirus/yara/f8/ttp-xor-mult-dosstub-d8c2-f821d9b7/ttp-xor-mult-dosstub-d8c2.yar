rule TTP_XOR_MULT_DOSStub_d8c2 {
  strings:
    $key_d8c2 = { 8c aa [2] f8 b2 [2] bf b0 [2] f8 a1 [2] b6 ad [2] ba a7 [2] ad ac [2] b6 e2 [2] 8b }

  condition:
    any of them
}