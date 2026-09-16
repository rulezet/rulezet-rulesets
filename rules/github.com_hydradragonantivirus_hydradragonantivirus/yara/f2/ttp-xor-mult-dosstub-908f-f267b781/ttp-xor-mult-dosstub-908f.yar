rule TTP_XOR_MULT_DOSStub_908f {
  strings:
    $key_908f = { c4 e7 [2] b0 ff [2] f7 fd [2] b0 ec [2] fe e0 [2] f2 ea [2] e5 e1 [2] fe af [2] c3 }

  condition:
    any of them
}