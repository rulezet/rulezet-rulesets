rule TTP_XOR_MULT_DOSStub_a296 {
  strings:
    $key_a296 = { f6 fe [2] 82 e6 [2] c5 e4 [2] 82 f5 [2] cc f9 [2] c0 f3 [2] d7 f8 [2] cc b6 [2] f1 }

  condition:
    any of them
}