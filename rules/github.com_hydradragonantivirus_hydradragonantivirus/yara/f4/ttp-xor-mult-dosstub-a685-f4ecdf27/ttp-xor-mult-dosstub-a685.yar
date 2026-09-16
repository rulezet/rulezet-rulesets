rule TTP_XOR_MULT_DOSStub_a685 {
  strings:
    $key_a685 = { f2 ed [2] 86 f5 [2] c1 f7 [2] 86 e6 [2] c8 ea [2] c4 e0 [2] d3 eb [2] c8 a5 [2] f5 }

  condition:
    any of them
}