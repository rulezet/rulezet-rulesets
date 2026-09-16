rule TTP_XOR_MULT_DOSStub_bc85 {
  strings:
    $key_bc85 = { e8 ed [2] 9c f5 [2] db f7 [2] 9c e6 [2] d2 ea [2] de e0 [2] c9 eb [2] d2 a5 [2] ef }

  condition:
    any of them
}