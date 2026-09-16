rule TTP_XOR_MULT_DOSStub_bc82 {
  strings:
    $key_bc82 = { e8 ea [2] 9c f2 [2] db f0 [2] 9c e1 [2] d2 ed [2] de e7 [2] c9 ec [2] d2 a2 [2] ef }

  condition:
    any of them
}