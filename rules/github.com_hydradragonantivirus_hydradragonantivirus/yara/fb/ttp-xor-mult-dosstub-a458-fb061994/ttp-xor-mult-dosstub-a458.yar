rule TTP_XOR_MULT_DOSStub_a458 {
  strings:
    $key_a458 = { f0 30 [2] 84 28 [2] c3 2a [2] 84 3b [2] ca 37 [2] c6 3d [2] d1 36 [2] ca 78 [2] f7 }

  condition:
    any of them
}