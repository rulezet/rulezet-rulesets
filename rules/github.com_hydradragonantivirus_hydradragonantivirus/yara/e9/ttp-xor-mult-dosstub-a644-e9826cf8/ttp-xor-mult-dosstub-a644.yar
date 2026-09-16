rule TTP_XOR_MULT_DOSStub_a644 {
  strings:
    $key_a644 = { f2 2c [2] 86 34 [2] c1 36 [2] 86 27 [2] c8 2b [2] c4 21 [2] d3 2a [2] c8 64 [2] f5 }

  condition:
    any of them
}