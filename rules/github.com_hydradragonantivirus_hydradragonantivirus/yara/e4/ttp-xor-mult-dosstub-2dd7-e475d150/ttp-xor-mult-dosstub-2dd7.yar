rule TTP_XOR_MULT_DOSStub_2dd7 {
  strings:
    $key_2dd7 = { 79 bf [2] 0d a7 [2] 4a a5 [2] 0d b4 [2] 43 b8 [2] 4f b2 [2] 58 b9 [2] 43 f7 [2] 7e }

  condition:
    any of them
}