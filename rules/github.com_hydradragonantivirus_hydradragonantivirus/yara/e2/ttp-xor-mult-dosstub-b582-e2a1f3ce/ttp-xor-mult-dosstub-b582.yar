rule TTP_XOR_MULT_DOSStub_b582 {
  strings:
    $key_b582 = { e1 ea [2] 95 f2 [2] d2 f0 [2] 95 e1 [2] db ed [2] d7 e7 [2] c0 ec [2] db a2 [2] e6 }

  condition:
    any of them
}