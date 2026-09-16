rule TTP_XOR_MULT_DOSStub_b68f {
  strings:
    $key_b68f = { e2 e7 [2] 96 ff [2] d1 fd [2] 96 ec [2] d8 e0 [2] d4 ea [2] c3 e1 [2] d8 af [2] e5 }

  condition:
    any of them
}