rule TTP_XOR_MULT_DOSStub_d6c2 {
  strings:
    $key_d6c2 = { 82 aa [2] f6 b2 [2] b1 b0 [2] f6 a1 [2] b8 ad [2] b4 a7 [2] a3 ac [2] b8 e2 [2] 85 }

  condition:
    any of them
}