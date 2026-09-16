rule TTP_XOR_MULT_DOSStub_a4c4 {
  strings:
    $key_a4c4 = { f0 ac [2] 84 b4 [2] c3 b6 [2] 84 a7 [2] ca ab [2] c6 a1 [2] d1 aa [2] ca e4 [2] f7 }

  condition:
    any of them
}