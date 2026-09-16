rule TTP_XOR_MULT_DOSStub_69d7 {
  strings:
    $key_69d7 = { 3d bf [2] 49 a7 [2] 0e a5 [2] 49 b4 [2] 07 b8 [2] 0b b2 [2] 1c b9 [2] 07 f7 [2] 3a }

  condition:
    any of them
}