rule TTP_XOR_MULT_DOSStub_a666 {
  strings:
    $key_a666 = { f2 0e [2] 86 16 [2] c1 14 [2] 86 05 [2] c8 09 [2] c4 03 [2] d3 08 [2] c8 46 [2] f5 }

  condition:
    any of them
}