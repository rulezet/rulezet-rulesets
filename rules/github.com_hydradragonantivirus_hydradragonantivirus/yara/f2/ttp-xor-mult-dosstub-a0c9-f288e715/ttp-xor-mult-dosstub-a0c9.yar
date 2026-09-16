rule TTP_XOR_MULT_DOSStub_a0c9 {
  strings:
    $key_a0c9 = { f4 a1 [2] 80 b9 [2] c7 bb [2] 80 aa [2] ce a6 [2] c2 ac [2] d5 a7 [2] ce e9 [2] f3 }

  condition:
    any of them
}