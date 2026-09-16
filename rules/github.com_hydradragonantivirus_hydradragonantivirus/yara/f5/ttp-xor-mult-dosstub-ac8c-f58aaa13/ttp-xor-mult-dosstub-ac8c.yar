rule TTP_XOR_MULT_DOSStub_ac8c {
  strings:
    $key_ac8c = { f8 e4 [2] 8c fc [2] cb fe [2] 8c ef [2] c2 e3 [2] ce e9 [2] d9 e2 [2] c2 ac [2] ff }

  condition:
    any of them
}