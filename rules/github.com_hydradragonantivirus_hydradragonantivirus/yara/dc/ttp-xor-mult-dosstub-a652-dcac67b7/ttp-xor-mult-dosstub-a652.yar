rule TTP_XOR_MULT_DOSStub_a652 {
  strings:
    $key_a652 = { f2 3a [2] 86 22 [2] c1 20 [2] 86 31 [2] c8 3d [2] c4 37 [2] d3 3c [2] c8 72 [2] f5 }

  condition:
    any of them
}