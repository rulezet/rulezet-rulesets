rule TTP_XOR_MULT_DOSStub_d4de {
  strings:
    $key_d4de = { 80 b6 [2] f4 ae [2] b3 ac [2] f4 bd [2] ba b1 [2] b6 bb [2] a1 b0 [2] ba fe [2] 87 }

  condition:
    any of them
}