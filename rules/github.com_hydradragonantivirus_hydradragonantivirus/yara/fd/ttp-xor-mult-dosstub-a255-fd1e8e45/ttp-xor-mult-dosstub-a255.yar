rule TTP_XOR_MULT_DOSStub_a255 {
  strings:
    $key_a255 = { f6 3d [2] 82 25 [2] c5 27 [2] 82 36 [2] cc 3a [2] c0 30 [2] d7 3b [2] cc 75 [2] f1 }

  condition:
    any of them
}