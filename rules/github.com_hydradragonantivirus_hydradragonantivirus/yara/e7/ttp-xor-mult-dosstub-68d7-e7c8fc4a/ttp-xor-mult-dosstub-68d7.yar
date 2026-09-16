rule TTP_XOR_MULT_DOSStub_68d7 {
  strings:
    $key_68d7 = { 3c bf [2] 48 a7 [2] 0f a5 [2] 48 b4 [2] 06 b8 [2] 0a b2 [2] 1d b9 [2] 06 f7 [2] 3b }

  condition:
    any of them
}