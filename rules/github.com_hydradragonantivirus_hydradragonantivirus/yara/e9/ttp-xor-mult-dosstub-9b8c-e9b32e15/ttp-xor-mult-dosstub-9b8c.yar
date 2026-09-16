rule TTP_XOR_MULT_DOSStub_9b8c {
  strings:
    $key_9b8c = { cf e4 [2] bb fc [2] fc fe [2] bb ef [2] f5 e3 [2] f9 e9 [2] ee e2 [2] f5 ac [2] c8 }

  condition:
    any of them
}