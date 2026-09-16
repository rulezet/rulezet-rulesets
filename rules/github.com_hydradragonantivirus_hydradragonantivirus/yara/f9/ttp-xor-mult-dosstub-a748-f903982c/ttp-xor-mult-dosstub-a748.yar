rule TTP_XOR_MULT_DOSStub_a748 {
  strings:
    $key_a748 = { f3 20 [2] 87 38 [2] c0 3a [2] 87 2b [2] c9 27 [2] c5 2d [2] d2 26 [2] c9 68 [2] f4 }

  condition:
    any of them
}