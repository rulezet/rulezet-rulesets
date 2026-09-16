rule TTP_XOR_MULT_DOSStub_b6de {
  strings:
    $key_b6de = { e2 b6 [2] 96 ae [2] d1 ac [2] 96 bd [2] d8 b1 [2] d4 bb [2] c3 b0 [2] d8 fe [2] e5 }

  condition:
    any of them
}