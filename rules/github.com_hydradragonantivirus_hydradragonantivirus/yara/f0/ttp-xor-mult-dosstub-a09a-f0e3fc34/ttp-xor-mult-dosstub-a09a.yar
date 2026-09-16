rule TTP_XOR_MULT_DOSStub_a09a {
  strings:
    $key_a09a = { f4 f2 [2] 80 ea [2] c7 e8 [2] 80 f9 [2] ce f5 [2] c2 ff [2] d5 f4 [2] ce ba [2] f3 }

  condition:
    any of them
}