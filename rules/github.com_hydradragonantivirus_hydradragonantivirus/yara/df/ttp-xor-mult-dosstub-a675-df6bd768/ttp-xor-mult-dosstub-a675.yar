rule TTP_XOR_MULT_DOSStub_a675 {
  strings:
    $key_a675 = { f2 1d [2] 86 05 [2] c1 07 [2] 86 16 [2] c8 1a [2] c4 10 [2] d3 1b [2] c8 55 [2] f5 }

  condition:
    any of them
}