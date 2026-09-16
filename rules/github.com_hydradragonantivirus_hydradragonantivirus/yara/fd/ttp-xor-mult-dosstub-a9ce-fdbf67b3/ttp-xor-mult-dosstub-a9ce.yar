rule TTP_XOR_MULT_DOSStub_a9ce {
  strings:
    $key_a9ce = { fd a6 [2] 89 be [2] ce bc [2] 89 ad [2] c7 a1 [2] cb ab [2] dc a0 [2] c7 ee [2] fa }

  condition:
    any of them
}