rule TTP_XOR_MULT_DOSStub_eace {
  strings:
    $key_eace = { be a6 [2] ca be [2] 8d bc [2] ca ad [2] 84 a1 [2] 88 ab [2] 9f a0 [2] 84 ee [2] b9 }

  condition:
    any of them
}