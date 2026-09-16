rule TTP_XOR_MULT_DOSStub_a2d0 {
  strings:
    $key_a2d0 = { f6 b8 [2] 82 a0 [2] c5 a2 [2] 82 b3 [2] cc bf [2] c0 b5 [2] d7 be [2] cc f0 [2] f1 }

  condition:
    any of them
}