rule TTP_XOR_MULT_DOSStub_3fd7 {
  strings:
    $key_3fd7 = { 6b bf [2] 1f a7 [2] 58 a5 [2] 1f b4 [2] 51 b8 [2] 5d b2 [2] 4a b9 [2] 51 f7 [2] 6c }

  condition:
    any of them
}