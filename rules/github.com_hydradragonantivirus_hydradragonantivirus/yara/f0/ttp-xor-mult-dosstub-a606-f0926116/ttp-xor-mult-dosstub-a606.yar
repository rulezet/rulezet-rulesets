rule TTP_XOR_MULT_DOSStub_a606 {
  strings:
    $key_a606 = { f2 6e [2] 86 76 [2] c1 74 [2] 86 65 [2] c8 69 [2] c4 63 [2] d3 68 [2] c8 26 [2] f5 }

  condition:
    any of them
}