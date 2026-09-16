rule TTP_XOR_MULT_DOSStub_918f {
  strings:
    $key_918f = { c5 e7 [2] b1 ff [2] f6 fd [2] b1 ec [2] ff e0 [2] f3 ea [2] e4 e1 [2] ff af [2] c2 }

  condition:
    any of them
}