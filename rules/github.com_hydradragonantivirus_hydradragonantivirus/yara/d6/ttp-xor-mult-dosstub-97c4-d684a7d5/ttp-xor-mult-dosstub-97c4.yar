rule TTP_XOR_MULT_DOSStub_97c4 {
  strings:
    $key_97c4 = { c3 ac [2] b7 b4 [2] f0 b6 [2] b7 a7 [2] f9 ab [2] f5 a1 [2] e2 aa [2] f9 e4 [2] c4 }

  condition:
    any of them
}