rule TTP_XOR_MULT_DOSStub_68d6 {
  strings:
    $key_68d6 = { 3c be [2] 48 a6 [2] 0f a4 [2] 48 b5 [2] 06 b9 [2] 0a b3 [2] 1d b8 [2] 06 f6 [2] 3b }

  condition:
    any of them
}