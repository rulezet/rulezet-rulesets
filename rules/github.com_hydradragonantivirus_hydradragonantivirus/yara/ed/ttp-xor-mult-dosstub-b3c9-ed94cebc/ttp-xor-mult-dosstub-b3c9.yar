rule TTP_XOR_MULT_DOSStub_b3c9 {
  strings:
    $key_b3c9 = { e7 a1 [2] 93 b9 [2] d4 bb [2] 93 aa [2] dd a6 [2] d1 ac [2] c6 a7 [2] dd e9 [2] e0 }

  condition:
    any of them
}