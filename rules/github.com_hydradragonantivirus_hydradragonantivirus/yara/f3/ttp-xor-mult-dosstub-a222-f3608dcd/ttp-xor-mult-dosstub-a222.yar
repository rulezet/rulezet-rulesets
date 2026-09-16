rule TTP_XOR_MULT_DOSStub_a222 {
  strings:
    $key_a222 = { f6 4a [2] 82 52 [2] c5 50 [2] 82 41 [2] cc 4d [2] c0 47 [2] d7 4c [2] cc 02 [2] f1 }

  condition:
    any of them
}