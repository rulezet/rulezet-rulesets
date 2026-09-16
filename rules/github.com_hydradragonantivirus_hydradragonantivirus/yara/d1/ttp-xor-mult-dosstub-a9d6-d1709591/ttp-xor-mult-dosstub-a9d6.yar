rule TTP_XOR_MULT_DOSStub_a9d6 {
  strings:
    $key_a9d6 = { fd be [2] 89 a6 [2] ce a4 [2] 89 b5 [2] c7 b9 [2] cb b3 [2] dc b8 [2] c7 f6 [2] fa }

  condition:
    any of them
}