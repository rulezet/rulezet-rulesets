rule TTP_XOR_MULT_DOSStub_b6ca {
  strings:
    $key_b6ca = { e2 a2 [2] 96 ba [2] d1 b8 [2] 96 a9 [2] d8 a5 [2] d4 af [2] c3 a4 [2] d8 ea [2] e5 }

  condition:
    any of them
}