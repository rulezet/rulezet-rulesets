rule TTP_XOR_MULT_DOSStub_f4de {
  strings:
    $key_f4de = { a0 b6 [2] d4 ae [2] 93 ac [2] d4 bd [2] 9a b1 [2] 96 bb [2] 81 b0 [2] 9a fe [2] a7 }

  condition:
    any of them
}