rule TTP_XOR_MULT_DOSStub_a9b9 {
  strings:
    $key_a9b9 = { fd d1 [2] 89 c9 [2] ce cb [2] 89 da [2] c7 d6 [2] cb dc [2] dc d7 [2] c7 99 [2] fa }

  condition:
    any of them
}