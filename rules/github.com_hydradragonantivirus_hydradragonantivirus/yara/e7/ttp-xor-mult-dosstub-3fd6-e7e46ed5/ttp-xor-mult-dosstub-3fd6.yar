rule TTP_XOR_MULT_DOSStub_3fd6 {
  strings:
    $key_3fd6 = { 6b be [2] 1f a6 [2] 58 a4 [2] 1f b5 [2] 51 b9 [2] 5d b3 [2] 4a b8 [2] 51 f6 [2] 6c }

  condition:
    any of them
}