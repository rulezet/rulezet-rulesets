rule TTP_XOR_MULT_DOSStub_a286 {
  strings:
    $key_a286 = { f6 ee [2] 82 f6 [2] c5 f4 [2] 82 e5 [2] cc e9 [2] c0 e3 [2] d7 e8 [2] cc a6 [2] f1 }

  condition:
    any of them
}