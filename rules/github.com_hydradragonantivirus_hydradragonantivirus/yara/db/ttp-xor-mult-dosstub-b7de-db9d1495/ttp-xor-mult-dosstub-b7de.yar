rule TTP_XOR_MULT_DOSStub_b7de {
  strings:
    $key_b7de = { e3 b6 [2] 97 ae [2] d0 ac [2] 97 bd [2] d9 b1 [2] d5 bb [2] c2 b0 [2] d9 fe [2] e4 }

  condition:
    any of them
}