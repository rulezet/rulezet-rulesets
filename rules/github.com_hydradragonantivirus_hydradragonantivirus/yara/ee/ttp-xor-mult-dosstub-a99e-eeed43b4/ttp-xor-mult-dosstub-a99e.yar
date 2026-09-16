rule TTP_XOR_MULT_DOSStub_a99e {
  strings:
    $key_a99e = { fd f6 [2] 89 ee [2] ce ec [2] 89 fd [2] c7 f1 [2] cb fb [2] dc f0 [2] c7 be [2] fa }

  condition:
    any of them
}