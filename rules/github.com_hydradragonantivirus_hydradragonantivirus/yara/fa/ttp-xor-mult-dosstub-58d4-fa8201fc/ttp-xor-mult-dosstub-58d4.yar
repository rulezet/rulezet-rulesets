rule TTP_XOR_MULT_DOSStub_58d4 {
  strings:
    $key_58d4 = { 0c bc [2] 78 a4 [2] 3f a6 [2] 78 b7 [2] 36 bb [2] 3a b1 [2] 2d ba [2] 36 f4 [2] 0b }

  condition:
    any of them
}