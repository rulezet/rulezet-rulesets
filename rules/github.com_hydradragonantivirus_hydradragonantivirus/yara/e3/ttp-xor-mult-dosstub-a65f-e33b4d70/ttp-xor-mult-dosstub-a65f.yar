rule TTP_XOR_MULT_DOSStub_a65f {
  strings:
    $key_a65f = { f2 37 [2] 86 2f [2] c1 2d [2] 86 3c [2] c8 30 [2] c4 3a [2] d3 31 [2] c8 7f [2] f5 }

  condition:
    any of them
}