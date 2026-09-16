rule TTP_XOR_MULT_DOSStub_a9d2 {
  strings:
    $key_a9d2 = { fd ba [2] 89 a2 [2] ce a0 [2] 89 b1 [2] c7 bd [2] cb b7 [2] dc bc [2] c7 f2 [2] fa }

  condition:
    any of them
}