rule TTP_XOR_MULT_DOSStub_01ca {
  strings:
    $key_01ca = { 55 a2 [2] 21 ba [2] 66 b8 [2] 21 a9 [2] 6f a5 [2] 63 af [2] 74 a4 [2] 6f ea [2] 52 }

  condition:
    any of them
}