rule TTP_XOR_MULT_DOSStub_46ca {
  strings:
    $key_46ca = { 12 a2 [2] 66 ba [2] 21 b8 [2] 66 a9 [2] 28 a5 [2] 24 af [2] 33 a4 [2] 28 ea [2] 15 }

  condition:
    any of them
}