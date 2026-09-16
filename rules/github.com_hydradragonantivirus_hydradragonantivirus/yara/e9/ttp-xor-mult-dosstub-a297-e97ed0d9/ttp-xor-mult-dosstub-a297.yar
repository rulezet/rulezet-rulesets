rule TTP_XOR_MULT_DOSStub_a297 {
  strings:
    $key_a297 = { f6 ff [2] 82 e7 [2] c5 e5 [2] 82 f4 [2] cc f8 [2] c0 f2 [2] d7 f9 [2] cc b7 [2] f1 }

  condition:
    any of them
}