rule TTP_XOR_MULT_DOSStub_91de {
  strings:
    $key_91de = { c5 b6 [2] b1 ae [2] f6 ac [2] b1 bd [2] ff b1 [2] f3 bb [2] e4 b0 [2] ff fe [2] c2 }

  condition:
    any of them
}