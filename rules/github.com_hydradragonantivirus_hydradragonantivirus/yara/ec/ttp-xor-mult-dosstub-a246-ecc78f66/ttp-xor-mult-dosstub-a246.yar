rule TTP_XOR_MULT_DOSStub_a246 {
  strings:
    $key_a246 = { f6 2e [2] 82 36 [2] c5 34 [2] 82 25 [2] cc 29 [2] c0 23 [2] d7 28 [2] cc 66 [2] f1 }

  condition:
    any of them
}