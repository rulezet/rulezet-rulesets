rule TTP_XOR_MULT_DOSStub_a6e7 {
  strings:
    $key_a6e7 = { f2 8f [2] 86 97 [2] c1 95 [2] 86 84 [2] c8 88 [2] c4 82 [2] d3 89 [2] c8 c7 [2] f5 }

  condition:
    any of them
}