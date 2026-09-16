rule TTP_XOR_MULT_DOSStub_32de {
  strings:
    $key_32de = { 66 b6 [2] 12 ae [2] 55 ac [2] 12 bd [2] 5c b1 [2] 50 bb [2] 47 b0 [2] 5c fe [2] 61 }

  condition:
    any of them
}