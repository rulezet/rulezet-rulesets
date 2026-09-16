rule TTP_XOR_MULT_DOSStub_34de {
  strings:
    $key_34de = { 60 b6 [2] 14 ae [2] 53 ac [2] 14 bd [2] 5a b1 [2] 56 bb [2] 41 b0 [2] 5a fe [2] 67 }

  condition:
    any of them
}