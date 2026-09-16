rule TTP_XOR_MULT_DOSStub_b3de {
  strings:
    $key_b3de = { e7 b6 [2] 93 ae [2] d4 ac [2] 93 bd [2] dd b1 [2] d1 bb [2] c6 b0 [2] dd fe [2] e0 }

  condition:
    any of them
}