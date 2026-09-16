rule TTP_XOR_MULT_DOSStub_a995 {
  strings:
    $key_a995 = { fd fd [2] 89 e5 [2] ce e7 [2] 89 f6 [2] c7 fa [2] cb f0 [2] dc fb [2] c7 b5 [2] fa }

  condition:
    any of them
}