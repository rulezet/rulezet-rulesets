rule TTP_XOR_MULT_DOSStub_a6ca {
  strings:
    $key_a6ca = { f2 a2 [2] 86 ba [2] c1 b8 [2] 86 a9 [2] c8 a5 [2] c4 af [2] d3 a4 [2] c8 ea [2] f5 }

  condition:
    any of them
}