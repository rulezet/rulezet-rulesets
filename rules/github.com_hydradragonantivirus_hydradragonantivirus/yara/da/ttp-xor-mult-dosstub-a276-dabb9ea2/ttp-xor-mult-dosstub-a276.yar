rule TTP_XOR_MULT_DOSStub_a276 {
  strings:
    $key_a276 = { f6 1e [2] 82 06 [2] c5 04 [2] 82 15 [2] cc 19 [2] c0 13 [2] d7 18 [2] cc 56 [2] f1 }

  condition:
    any of them
}