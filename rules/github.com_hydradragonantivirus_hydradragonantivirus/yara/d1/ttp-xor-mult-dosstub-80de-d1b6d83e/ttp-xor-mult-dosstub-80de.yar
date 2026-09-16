rule TTP_XOR_MULT_DOSStub_80de {
  strings:
    $key_80de = { d4 b6 [2] a0 ae [2] e7 ac [2] a0 bd [2] ee b1 [2] e2 bb [2] f5 b0 [2] ee fe [2] d3 }

  condition:
    any of them
}