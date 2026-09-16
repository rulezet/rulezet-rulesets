rule TTP_XOR_MULT_DOSStub_b38f {
  strings:
    $key_b38f = { e7 e7 [2] 93 ff [2] d4 fd [2] 93 ec [2] dd e0 [2] d1 ea [2] c6 e1 [2] dd af [2] e0 }

  condition:
    any of them
}