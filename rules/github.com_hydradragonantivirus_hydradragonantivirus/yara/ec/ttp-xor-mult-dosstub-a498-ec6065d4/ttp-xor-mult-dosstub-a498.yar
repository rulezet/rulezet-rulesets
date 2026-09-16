rule TTP_XOR_MULT_DOSStub_a498 {
  strings:
    $key_a498 = { f0 f0 [2] 84 e8 [2] c3 ea [2] 84 fb [2] ca f7 [2] c6 fd [2] d1 f6 [2] ca b8 [2] f7 }

  condition:
    any of them
}