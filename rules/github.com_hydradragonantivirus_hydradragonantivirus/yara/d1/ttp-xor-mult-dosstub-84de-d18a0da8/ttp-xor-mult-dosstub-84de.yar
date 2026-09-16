rule TTP_XOR_MULT_DOSStub_84de {
  strings:
    $key_84de = { d0 b6 [2] a4 ae [2] e3 ac [2] a4 bd [2] ea b1 [2] e6 bb [2] f1 b0 [2] ea fe [2] d7 }

  condition:
    any of them
}