rule TTP_XOR_MULT_DOSStub_86c9 {
  strings:
    $key_86c9 = { d2 a1 [2] a6 b9 [2] e1 bb [2] a6 aa [2] e8 a6 [2] e4 ac [2] f3 a7 [2] e8 e9 [2] d5 }

  condition:
    any of them
}