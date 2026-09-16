rule TTP_XOR_MULT_DOSStub_73ca {
  strings:
    $key_73ca = { 27 a2 [2] 53 ba [2] 14 b8 [2] 53 a9 [2] 1d a5 [2] 11 af [2] 06 a4 [2] 1d ea [2] 20 }

  condition:
    any of them
}