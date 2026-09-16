rule TTP_XOR_MULT_DOSStub_a632 {
  strings:
    $key_a632 = { f2 5a [2] 86 42 [2] c1 40 [2] 86 51 [2] c8 5d [2] c4 57 [2] d3 5c [2] c8 12 [2] f5 }

  condition:
    any of them
}