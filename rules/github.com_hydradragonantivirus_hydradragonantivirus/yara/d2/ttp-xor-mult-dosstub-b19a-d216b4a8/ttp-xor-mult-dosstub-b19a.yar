rule TTP_XOR_MULT_DOSStub_b19a {
  strings:
    $key_b19a = { e5 f2 [2] 91 ea [2] d6 e8 [2] 91 f9 [2] df f5 [2] d3 ff [2] c4 f4 [2] df ba [2] e2 }

  condition:
    any of them
}