rule TTP_XOR_MULT_DOSStub_28d6 {
  strings:
    $key_28d6 = { 7c be [2] 08 a6 [2] 4f a4 [2] 08 b5 [2] 46 b9 [2] 4a b3 [2] 5d b8 [2] 46 f6 [2] 7b }

  condition:
    any of them
}