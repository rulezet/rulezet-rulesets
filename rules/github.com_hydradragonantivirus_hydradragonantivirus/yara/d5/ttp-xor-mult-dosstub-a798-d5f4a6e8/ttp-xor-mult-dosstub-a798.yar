rule TTP_XOR_MULT_DOSStub_a798 {
  strings:
    $key_a798 = { f3 f0 [2] 87 e8 [2] c0 ea [2] 87 fb [2] c9 f7 [2] c5 fd [2] d2 f6 [2] c9 b8 [2] f4 }

  condition:
    any of them
}