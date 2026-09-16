rule TTP_XOR_MULT_DOSStub_03ca {
  strings:
    $key_03ca = { 57 a2 [2] 23 ba [2] 64 b8 [2] 23 a9 [2] 6d a5 [2] 61 af [2] 76 a4 [2] 6d ea [2] 50 }

  condition:
    any of them
}