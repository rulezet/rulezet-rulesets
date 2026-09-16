rule TTP_XOR_MULT_DOSStub_b0de {
  strings:
    $key_b0de = { e4 b6 [2] 90 ae [2] d7 ac [2] 90 bd [2] de b1 [2] d2 bb [2] c5 b0 [2] de fe [2] e3 }

  condition:
    any of them
}