rule TTP_XOR_MULT_DOSStub_a9c3 {
  strings:
    $key_a9c3 = { fd ab [2] 89 b3 [2] ce b1 [2] 89 a0 [2] c7 ac [2] cb a6 [2] dc ad [2] c7 e3 [2] fa }

  condition:
    any of them
}