rule TTP_XOR_MULT_DOSStub_a9d7 {
  strings:
    $key_a9d7 = { fd bf [2] 89 a7 [2] ce a5 [2] 89 b4 [2] c7 b8 [2] cb b2 [2] dc b9 [2] c7 f7 [2] fa }

  condition:
    any of them
}