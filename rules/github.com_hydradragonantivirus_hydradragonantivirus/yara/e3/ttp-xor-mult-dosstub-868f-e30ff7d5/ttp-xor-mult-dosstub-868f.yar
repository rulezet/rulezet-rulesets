rule TTP_XOR_MULT_DOSStub_868f {
  strings:
    $key_868f = { d2 e7 [2] a6 ff [2] e1 fd [2] a6 ec [2] e8 e0 [2] e4 ea [2] f3 e1 [2] e8 af [2] d5 }

  condition:
    any of them
}