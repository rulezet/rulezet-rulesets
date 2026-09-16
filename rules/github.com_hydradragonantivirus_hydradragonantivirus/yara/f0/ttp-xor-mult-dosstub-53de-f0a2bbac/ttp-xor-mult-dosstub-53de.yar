rule TTP_XOR_MULT_DOSStub_53de {
  strings:
    $key_53de = { 07 b6 [2] 73 ae [2] 34 ac [2] 73 bd [2] 3d b1 [2] 31 bb [2] 26 b0 [2] 3d fe [2] 00 }

  condition:
    any of them
}