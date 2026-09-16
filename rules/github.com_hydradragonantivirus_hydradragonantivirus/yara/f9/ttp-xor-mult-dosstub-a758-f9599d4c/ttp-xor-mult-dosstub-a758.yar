rule TTP_XOR_MULT_DOSStub_a758 {
  strings:
    $key_a758 = { f3 30 [2] 87 28 [2] c0 2a [2] 87 3b [2] c9 37 [2] c5 3d [2] d2 36 [2] c9 78 [2] f4 }

  condition:
    any of them
}