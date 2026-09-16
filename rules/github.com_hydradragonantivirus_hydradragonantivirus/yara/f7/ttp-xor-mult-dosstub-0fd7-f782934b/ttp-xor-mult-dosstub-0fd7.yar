rule TTP_XOR_MULT_DOSStub_0fd7 {
  strings:
    $key_0fd7 = { 5b bf [2] 2f a7 [2] 68 a5 [2] 2f b4 [2] 61 b8 [2] 6d b2 [2] 7a b9 [2] 61 f7 [2] 5c }

  condition:
    any of them
}