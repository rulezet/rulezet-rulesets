rule TTP_XOR_MULT_DOSStub_a615 {
  strings:
    $key_a615 = { f2 7d [2] 86 65 [2] c1 67 [2] 86 76 [2] c8 7a [2] c4 70 [2] d3 7b [2] c8 35 [2] f5 }

  condition:
    any of them
}