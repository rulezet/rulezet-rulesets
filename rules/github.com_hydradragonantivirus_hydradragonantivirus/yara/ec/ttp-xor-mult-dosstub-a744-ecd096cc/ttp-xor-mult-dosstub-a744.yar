rule TTP_XOR_MULT_DOSStub_a744 {
  strings:
    $key_a744 = { f3 2c [2] 87 34 [2] c0 36 [2] 87 27 [2] c9 2b [2] c5 21 [2] d2 2a [2] c9 64 [2] f4 }

  condition:
    any of them
}