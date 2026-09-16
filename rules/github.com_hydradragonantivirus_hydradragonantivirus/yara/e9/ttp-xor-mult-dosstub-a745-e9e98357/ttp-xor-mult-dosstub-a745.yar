rule TTP_XOR_MULT_DOSStub_a745 {
  strings:
    $key_a745 = { f3 2d [2] 87 35 [2] c0 37 [2] 87 26 [2] c9 2a [2] c5 20 [2] d2 2b [2] c9 65 [2] f4 }

  condition:
    any of them
}