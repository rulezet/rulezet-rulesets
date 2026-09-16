rule TTP_XOR_MULT_DOSStub_67de {
  strings:
    $key_67de = { 33 b6 [2] 47 ae [2] 00 ac [2] 47 bd [2] 09 b1 [2] 05 bb [2] 12 b0 [2] 09 fe [2] 34 }

  condition:
    any of them
}