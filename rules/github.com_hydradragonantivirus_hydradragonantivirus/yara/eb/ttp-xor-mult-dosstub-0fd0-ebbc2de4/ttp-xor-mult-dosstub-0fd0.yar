rule TTP_XOR_MULT_DOSStub_0fd0 {
  strings:
    $key_0fd0 = { 5b b8 [2] 2f a0 [2] 68 a2 [2] 2f b3 [2] 61 bf [2] 6d b5 [2] 7a be [2] 61 f0 [2] 5c }

  condition:
    any of them
}