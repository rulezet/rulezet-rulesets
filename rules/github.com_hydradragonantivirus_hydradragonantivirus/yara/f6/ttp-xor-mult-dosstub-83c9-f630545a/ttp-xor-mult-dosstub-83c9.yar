rule TTP_XOR_MULT_DOSStub_83c9 {
  strings:
    $key_83c9 = { d7 a1 [2] a3 b9 [2] e4 bb [2] a3 aa [2] ed a6 [2] e1 ac [2] f6 a7 [2] ed e9 [2] d0 }

  condition:
    any of them
}