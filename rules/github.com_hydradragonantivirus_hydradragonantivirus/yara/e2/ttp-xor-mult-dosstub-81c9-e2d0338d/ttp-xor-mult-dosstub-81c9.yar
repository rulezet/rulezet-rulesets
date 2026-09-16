rule TTP_XOR_MULT_DOSStub_81c9 {
  strings:
    $key_81c9 = { d5 a1 [2] a1 b9 [2] e6 bb [2] a1 aa [2] ef a6 [2] e3 ac [2] f4 a7 [2] ef e9 [2] d2 }

  condition:
    any of them
}