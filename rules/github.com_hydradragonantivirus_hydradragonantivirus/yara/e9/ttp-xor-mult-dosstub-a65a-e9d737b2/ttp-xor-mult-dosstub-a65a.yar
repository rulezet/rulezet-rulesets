rule TTP_XOR_MULT_DOSStub_a65a {
  strings:
    $key_a65a = { f2 32 [2] 86 2a [2] c1 28 [2] 86 39 [2] c8 35 [2] c4 3f [2] d3 34 [2] c8 7a [2] f5 }

  condition:
    any of them
}