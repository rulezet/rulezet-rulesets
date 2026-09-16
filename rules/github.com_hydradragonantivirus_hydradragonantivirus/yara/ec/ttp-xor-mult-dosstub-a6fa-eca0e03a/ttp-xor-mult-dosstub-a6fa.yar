rule TTP_XOR_MULT_DOSStub_a6fa {
  strings:
    $key_a6fa = { f2 92 [2] 86 8a [2] c1 88 [2] 86 99 [2] c8 95 [2] c4 9f [2] d3 94 [2] c8 da [2] f5 }

  condition:
    any of them
}