rule TTP_XOR_MULT_DOSStub_a18f {
  strings:
    $key_a18f = { f5 e7 [2] 81 ff [2] c6 fd [2] 81 ec [2] cf e0 [2] c3 ea [2] d4 e1 [2] cf af [2] f2 }

  condition:
    any of them
}