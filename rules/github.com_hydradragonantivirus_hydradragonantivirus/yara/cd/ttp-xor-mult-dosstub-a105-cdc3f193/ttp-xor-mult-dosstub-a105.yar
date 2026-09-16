rule TTP_XOR_MULT_DOSStub_a105 {
  strings:
    $key_a105 = { f5 6d [2] 81 75 [2] c6 77 [2] 81 66 [2] cf 6a [2] c3 60 [2] d4 6b [2] cf 25 [2] f2 }

  condition:
    any of them
}