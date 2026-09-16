rule TTP_XOR_MULT_DOSStub_40de {
  strings:
    $key_40de = { 14 b6 [2] 60 ae [2] 27 ac [2] 60 bd [2] 2e b1 [2] 22 bb [2] 35 b0 [2] 2e fe [2] 13 }

  condition:
    any of them
}