rule TTP_XOR_MULT_DOSStub_a252 {
  strings:
    $key_a252 = { f6 3a [2] 82 22 [2] c5 20 [2] 82 31 [2] cc 3d [2] c0 37 [2] d7 3c [2] cc 72 [2] f1 }

  condition:
    any of them
}