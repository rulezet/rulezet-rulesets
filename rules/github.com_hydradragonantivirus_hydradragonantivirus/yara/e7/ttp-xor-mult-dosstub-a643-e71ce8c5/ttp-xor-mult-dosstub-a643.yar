rule TTP_XOR_MULT_DOSStub_a643 {
  strings:
    $key_a643 = { f2 2b [2] 86 33 [2] c1 31 [2] 86 20 [2] c8 2c [2] c4 26 [2] d3 2d [2] c8 63 [2] f5 }

  condition:
    any of them
}