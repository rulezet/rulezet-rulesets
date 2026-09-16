rule TTP_XOR_MULT_DOSStub_dd9a {
  strings:
    $key_dd9a = { 89 f2 [2] fd ea [2] ba e8 [2] fd f9 [2] b3 f5 [2] bf ff [2] a8 f4 [2] b3 ba [2] 8e }

  condition:
    any of them
}