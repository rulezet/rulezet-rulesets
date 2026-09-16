rule TTP_XOR_MULT_DOSStub_69d2 {
  strings:
    $key_69d2 = { 3d ba [2] 49 a2 [2] 0e a0 [2] 49 b1 [2] 07 bd [2] 0b b7 [2] 1c bc [2] 07 f2 [2] 3a }

  condition:
    any of them
}