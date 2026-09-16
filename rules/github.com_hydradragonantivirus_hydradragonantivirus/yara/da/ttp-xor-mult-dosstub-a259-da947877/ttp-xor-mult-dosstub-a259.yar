rule TTP_XOR_MULT_DOSStub_a259 {
  strings:
    $key_a259 = { f6 31 [2] 82 29 [2] c5 2b [2] 82 3a [2] cc 36 [2] c0 3c [2] d7 37 [2] cc 79 [2] f1 }

  condition:
    any of them
}