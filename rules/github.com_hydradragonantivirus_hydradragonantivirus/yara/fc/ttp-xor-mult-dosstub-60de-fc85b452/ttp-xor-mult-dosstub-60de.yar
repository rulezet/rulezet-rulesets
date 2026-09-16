rule TTP_XOR_MULT_DOSStub_60de {
  strings:
    $key_60de = { 34 b6 [2] 40 ae [2] 07 ac [2] 40 bd [2] 0e b1 [2] 02 bb [2] 15 b0 [2] 0e fe [2] 33 }

  condition:
    any of them
}