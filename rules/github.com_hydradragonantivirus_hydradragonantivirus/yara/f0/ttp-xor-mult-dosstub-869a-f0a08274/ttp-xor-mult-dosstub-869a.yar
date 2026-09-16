rule TTP_XOR_MULT_DOSStub_869a {
  strings:
    $key_869a = { d2 f2 [2] a6 ea [2] e1 e8 [2] a6 f9 [2] e8 f5 [2] e4 ff [2] f3 f4 [2] e8 ba [2] d5 }

  condition:
    any of them
}