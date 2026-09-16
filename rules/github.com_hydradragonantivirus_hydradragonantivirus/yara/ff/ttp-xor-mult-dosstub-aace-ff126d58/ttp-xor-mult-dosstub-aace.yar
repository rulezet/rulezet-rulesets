rule TTP_XOR_MULT_DOSStub_aace {
  strings:
    $key_aace = { fe a6 [2] 8a be [2] cd bc [2] 8a ad [2] c4 a1 [2] c8 ab [2] df a0 [2] c4 ee [2] f9 }

  condition:
    any of them
}