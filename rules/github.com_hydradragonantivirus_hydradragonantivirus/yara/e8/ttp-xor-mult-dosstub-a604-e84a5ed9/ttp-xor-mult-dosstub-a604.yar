rule TTP_XOR_MULT_DOSStub_a604 {
  strings:
    $key_a604 = { f2 6c [2] 86 74 [2] c1 76 [2] 86 67 [2] c8 6b [2] c4 61 [2] d3 6a [2] c8 24 [2] f5 }

  condition:
    any of them
}