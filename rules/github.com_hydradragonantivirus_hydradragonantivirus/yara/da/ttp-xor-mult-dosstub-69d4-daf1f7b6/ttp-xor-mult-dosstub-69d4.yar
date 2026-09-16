rule TTP_XOR_MULT_DOSStub_69d4 {
  strings:
    $key_69d4 = { 3d bc [2] 49 a4 [2] 0e a6 [2] 49 b7 [2] 07 bb [2] 0b b1 [2] 1c ba [2] 07 f4 [2] 3a }

  condition:
    any of them
}