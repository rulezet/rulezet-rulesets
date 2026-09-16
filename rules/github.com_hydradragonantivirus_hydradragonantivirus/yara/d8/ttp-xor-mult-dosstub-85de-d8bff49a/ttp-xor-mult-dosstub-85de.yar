rule TTP_XOR_MULT_DOSStub_85de {
  strings:
    $key_85de = { d1 b6 [2] a5 ae [2] e2 ac [2] a5 bd [2] eb b1 [2] e7 bb [2] f0 b0 [2] eb fe [2] d6 }

  condition:
    any of them
}