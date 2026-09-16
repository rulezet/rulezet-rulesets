rule TTP_XOR_MULT_DOSStub_77de {
  strings:
    $key_77de = { 23 b6 [2] 57 ae [2] 10 ac [2] 57 bd [2] 19 b1 [2] 15 bb [2] 02 b0 [2] 19 fe [2] 24 }

  condition:
    any of them
}