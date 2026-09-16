rule TTP_XOR_MULT_DOSStub_a262 {
  strings:
    $key_a262 = { f6 0a [2] 82 12 [2] c5 10 [2] 82 01 [2] cc 0d [2] c0 07 [2] d7 0c [2] cc 42 [2] f1 }

  condition:
    any of them
}