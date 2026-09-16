rule TTP_XOR_MULT_DOSStub_b5c9 {
  strings:
    $key_b5c9 = { e1 a1 [2] 95 b9 [2] d2 bb [2] 95 aa [2] db a6 [2] d7 ac [2] c0 a7 [2] db e9 [2] e6 }

  condition:
    any of them
}