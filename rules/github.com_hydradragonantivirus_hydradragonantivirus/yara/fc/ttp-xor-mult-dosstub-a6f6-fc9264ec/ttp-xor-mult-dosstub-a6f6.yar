rule TTP_XOR_MULT_DOSStub_a6f6 {
  strings:
    $key_a6f6 = { f2 9e [2] 86 86 [2] c1 84 [2] 86 95 [2] c8 99 [2] c4 93 [2] d3 98 [2] c8 d6 [2] f5 }

  condition:
    any of them
}