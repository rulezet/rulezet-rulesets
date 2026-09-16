rule TTP_XOR_MULT_DOSStub_f0de {
  strings:
    $key_f0de = { a4 b6 [2] d0 ae [2] 97 ac [2] d0 bd [2] 9e b1 [2] 92 bb [2] 85 b0 [2] 9e fe [2] a3 }

  condition:
    any of them
}