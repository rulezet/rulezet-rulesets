rule TTP_XOR_MULT_DOSStub_a99b {
  strings:
    $key_a99b = { fd f3 [2] 89 eb [2] ce e9 [2] 89 f8 [2] c7 f4 [2] cb fe [2] dc f5 [2] c7 bb [2] fa }

  condition:
    any of them
}