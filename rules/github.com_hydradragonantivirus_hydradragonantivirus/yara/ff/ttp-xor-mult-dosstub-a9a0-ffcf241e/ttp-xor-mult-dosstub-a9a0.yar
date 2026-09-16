rule TTP_XOR_MULT_DOSStub_a9a0 {
  strings:
    $key_a9a0 = { fd c8 [2] 89 d0 [2] ce d2 [2] 89 c3 [2] c7 cf [2] cb c5 [2] dc ce [2] c7 80 [2] fa }

  condition:
    any of them
}