rule TTP_XOR_MULT_DOSStub_3fd0 {
  strings:
    $key_3fd0 = { 6b b8 [2] 1f a0 [2] 58 a2 [2] 1f b3 [2] 51 bf [2] 5d b5 [2] 4a be [2] 51 f0 [2] 6c }

  condition:
    any of them
}