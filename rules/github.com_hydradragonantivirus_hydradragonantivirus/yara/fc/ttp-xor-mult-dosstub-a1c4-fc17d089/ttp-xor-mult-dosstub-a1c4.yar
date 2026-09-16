rule TTP_XOR_MULT_DOSStub_a1c4 {
  strings:
    $key_a1c4 = { f5 ac [2] 81 b4 [2] c6 b6 [2] 81 a7 [2] cf ab [2] c3 a1 [2] d4 aa [2] cf e4 [2] f2 }

  condition:
    any of them
}