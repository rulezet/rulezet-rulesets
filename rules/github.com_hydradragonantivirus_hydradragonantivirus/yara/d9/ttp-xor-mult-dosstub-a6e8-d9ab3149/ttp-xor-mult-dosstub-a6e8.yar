rule TTP_XOR_MULT_DOSStub_a6e8 {
  strings:
    $key_a6e8 = { f2 80 [2] 86 98 [2] c1 9a [2] 86 8b [2] c8 87 [2] c4 8d [2] d3 86 [2] c8 c8 [2] f5 }

  condition:
    any of them
}