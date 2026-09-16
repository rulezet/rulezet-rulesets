rule TTP_XOR_MULT_DOSStub_e5de {
  strings:
    $key_e5de = { b1 b6 [2] c5 ae [2] 82 ac [2] c5 bd [2] 8b b1 [2] 87 bb [2] 90 b0 [2] 8b fe [2] b6 }

  condition:
    any of them
}