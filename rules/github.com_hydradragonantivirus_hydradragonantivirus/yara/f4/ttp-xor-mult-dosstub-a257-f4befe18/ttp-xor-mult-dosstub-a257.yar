rule TTP_XOR_MULT_DOSStub_a257 {
  strings:
    $key_a257 = { f6 3f [2] 82 27 [2] c5 25 [2] 82 34 [2] cc 38 [2] c0 32 [2] d7 39 [2] cc 77 [2] f1 }

  condition:
    any of them
}