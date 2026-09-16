rule TTP_XOR_MULT_DOSStub_7c8c {
  strings:
    $key_7c8c = { 28 e4 [2] 5c fc [2] 1b fe [2] 5c ef [2] 12 e3 [2] 1e e9 [2] 09 e2 [2] 12 ac [2] 2f }

  condition:
    any of them
}