rule TTP_XOR_MULT_DOSStub_f1ca {
  strings:
    $key_f1ca = { a5 a2 [2] d1 ba [2] 96 b8 [2] d1 a9 [2] 9f a5 [2] 93 af [2] 84 a4 [2] 9f ea [2] a2 }

  condition:
    any of them
}