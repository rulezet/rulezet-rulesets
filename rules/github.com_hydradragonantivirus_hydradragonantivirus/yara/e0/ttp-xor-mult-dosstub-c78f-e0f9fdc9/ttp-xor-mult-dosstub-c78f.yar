rule TTP_XOR_MULT_DOSStub_c78f {
  strings:
    $key_c78f = { 93 e7 [2] e7 ff [2] a0 fd [2] e7 ec [2] a9 e0 [2] a5 ea [2] b2 e1 [2] a9 af [2] 94 }

  condition:
    any of them
}