rule TTP_XOR_MULT_DOSStub_f2ca {
  strings:
    $key_f2ca = { a6 a2 [2] d2 ba [2] 95 b8 [2] d2 a9 [2] 9c a5 [2] 90 af [2] 87 a4 [2] 9c ea [2] a1 }

  condition:
    any of them
}