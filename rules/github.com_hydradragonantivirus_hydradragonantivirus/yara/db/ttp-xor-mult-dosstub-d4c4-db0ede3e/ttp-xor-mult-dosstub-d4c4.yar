rule TTP_XOR_MULT_DOSStub_d4c4 {
  strings:
    $key_d4c4 = { 80 ac [2] f4 b4 [2] b3 b6 [2] f4 a7 [2] ba ab [2] b6 a1 [2] a1 aa [2] ba e4 [2] 87 }

  condition:
    any of them
}