rule TTP_XOR_MULT_DOSStub_a5de {
  strings:
    $key_a5de = { f1 b6 [2] 85 ae [2] c2 ac [2] 85 bd [2] cb b1 [2] c7 bb [2] d0 b0 [2] cb fe [2] f6 }

  condition:
    any of them
}