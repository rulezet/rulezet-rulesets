rule TTP_XOR_MULT_DOSStub_a6e1 {
  strings:
    $key_a6e1 = { f2 89 [2] 86 91 [2] c1 93 [2] 86 82 [2] c8 8e [2] c4 84 [2] d3 8f [2] c8 c1 [2] f5 }

  condition:
    any of them
}