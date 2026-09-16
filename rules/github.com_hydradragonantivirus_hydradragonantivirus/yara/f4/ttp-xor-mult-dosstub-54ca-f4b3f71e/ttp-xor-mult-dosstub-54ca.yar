rule TTP_XOR_MULT_DOSStub_54ca {
  strings:
    $key_54ca = { 00 a2 [2] 74 ba [2] 33 b8 [2] 74 a9 [2] 3a a5 [2] 36 af [2] 21 a4 [2] 3a ea [2] 07 }

  condition:
    any of them
}