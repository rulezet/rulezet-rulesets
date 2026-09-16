rule TTP_XOR_MULT_DOSStub_00de {
  strings:
    $key_00de = { 54 b6 [2] 20 ae [2] 67 ac [2] 20 bd [2] 6e b1 [2] 62 bb [2] 75 b0 [2] 6e fe [2] 53 }

  condition:
    any of them
}