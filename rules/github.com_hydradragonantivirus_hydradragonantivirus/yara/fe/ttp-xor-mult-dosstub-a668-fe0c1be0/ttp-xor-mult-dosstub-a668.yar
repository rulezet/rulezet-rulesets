rule TTP_XOR_MULT_DOSStub_a668 {
  strings:
    $key_a668 = { f2 00 [2] 86 18 [2] c1 1a [2] 86 0b [2] c8 07 [2] c4 0d [2] d3 06 [2] c8 48 [2] f5 }

  condition:
    any of them
}