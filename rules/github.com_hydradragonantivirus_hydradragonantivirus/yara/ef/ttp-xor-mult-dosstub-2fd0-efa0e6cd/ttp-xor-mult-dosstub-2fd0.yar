rule TTP_XOR_MULT_DOSStub_2fd0 {
  strings:
    $key_2fd0 = { 7b b8 [2] 0f a0 [2] 48 a2 [2] 0f b3 [2] 41 bf [2] 4d b5 [2] 5a be [2] 41 f0 [2] 7c }

  condition:
    any of them
}