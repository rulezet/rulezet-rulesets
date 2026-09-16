rule TTP_XOR_MULT_DOSStub_cace {
  strings:
    $key_cace = { 9e a6 [2] ea be [2] ad bc [2] ea ad [2] a4 a1 [2] a8 ab [2] bf a0 [2] a4 ee [2] 99 }

  condition:
    any of them
}