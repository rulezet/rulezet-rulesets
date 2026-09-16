rule TTP_XOR_MULT_DOSStub_bc81 {
  strings:
    $key_bc81 = { e8 e9 [2] 9c f1 [2] db f3 [2] 9c e2 [2] d2 ee [2] de e4 [2] c9 ef [2] d2 a1 [2] ef }

  condition:
    any of them
}