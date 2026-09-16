rule TTP_XOR_MULT_DOSStub_31de {
  strings:
    $key_31de = { 65 b6 [2] 11 ae [2] 56 ac [2] 11 bd [2] 5f b1 [2] 53 bb [2] 44 b0 [2] 5f fe [2] 62 }

  condition:
    any of them
}