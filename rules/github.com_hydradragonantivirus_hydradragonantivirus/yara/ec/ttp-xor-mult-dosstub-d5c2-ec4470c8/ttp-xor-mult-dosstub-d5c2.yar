rule TTP_XOR_MULT_DOSStub_d5c2 {
  strings:
    $key_d5c2 = { 81 aa [2] f5 b2 [2] b2 b0 [2] f5 a1 [2] bb ad [2] b7 a7 [2] a0 ac [2] bb e2 [2] 86 }

  condition:
    any of them
}