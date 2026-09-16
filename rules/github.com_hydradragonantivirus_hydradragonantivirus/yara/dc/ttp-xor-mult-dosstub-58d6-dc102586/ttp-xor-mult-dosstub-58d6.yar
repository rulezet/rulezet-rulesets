rule TTP_XOR_MULT_DOSStub_58d6 {
  strings:
    $key_58d6 = { 0c be [2] 78 a6 [2] 3f a4 [2] 78 b5 [2] 36 b9 [2] 3a b3 [2] 2d b8 [2] 36 f6 [2] 0b }

  condition:
    any of them
}