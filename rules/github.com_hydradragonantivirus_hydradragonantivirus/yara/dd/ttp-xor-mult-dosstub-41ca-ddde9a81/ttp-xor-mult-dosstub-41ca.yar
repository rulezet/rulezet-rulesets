rule TTP_XOR_MULT_DOSStub_41ca {
  strings:
    $key_41ca = { 15 a2 [2] 61 ba [2] 26 b8 [2] 61 a9 [2] 2f a5 [2] 23 af [2] 34 a4 [2] 2f ea [2] 12 }

  condition:
    any of them
}