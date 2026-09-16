rule TTP_XOR_MULT_DOSStub_26de {
  strings:
    $key_26de = { 72 b6 [2] 06 ae [2] 41 ac [2] 06 bd [2] 48 b1 [2] 44 bb [2] 53 b0 [2] 48 fe [2] 75 }

  condition:
    any of them
}