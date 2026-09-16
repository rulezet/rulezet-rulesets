rule TTP_XOR_MULT_DOSStub_63de {
  strings:
    $key_63de = { 37 b6 [2] 43 ae [2] 04 ac [2] 43 bd [2] 0d b1 [2] 01 bb [2] 16 b0 [2] 0d fe [2] 30 }

  condition:
    any of them
}