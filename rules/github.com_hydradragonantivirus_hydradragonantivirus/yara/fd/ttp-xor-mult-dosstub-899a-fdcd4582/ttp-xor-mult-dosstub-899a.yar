rule TTP_XOR_MULT_DOSStub_899a {
  strings:
    $key_899a = { dd f2 [2] a9 ea [2] ee e8 [2] a9 f9 [2] e7 f5 [2] eb ff [2] fc f4 [2] e7 ba [2] da }

  condition:
    any of them
}