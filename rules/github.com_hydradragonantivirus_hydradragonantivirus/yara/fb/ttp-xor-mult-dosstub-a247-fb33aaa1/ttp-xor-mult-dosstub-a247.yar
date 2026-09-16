rule TTP_XOR_MULT_DOSStub_a247 {
  strings:
    $key_a247 = { f6 2f [2] 82 37 [2] c5 35 [2] 82 24 [2] cc 28 [2] c0 22 [2] d7 29 [2] cc 67 [2] f1 }

  condition:
    any of them
}