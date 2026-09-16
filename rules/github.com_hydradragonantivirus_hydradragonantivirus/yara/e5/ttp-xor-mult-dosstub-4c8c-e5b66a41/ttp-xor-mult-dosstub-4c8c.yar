rule TTP_XOR_MULT_DOSStub_4c8c {
  strings:
    $key_4c8c = { 18 e4 [2] 6c fc [2] 2b fe [2] 6c ef [2] 22 e3 [2] 2e e9 [2] 39 e2 [2] 22 ac [2] 1f }

  condition:
    any of them
}