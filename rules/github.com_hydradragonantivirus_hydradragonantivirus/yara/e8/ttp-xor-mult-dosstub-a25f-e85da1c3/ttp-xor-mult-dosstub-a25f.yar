rule TTP_XOR_MULT_DOSStub_a25f {
  strings:
    $key_a25f = { f6 37 [2] 82 2f [2] c5 2d [2] 82 3c [2] cc 30 [2] c0 3a [2] d7 31 [2] cc 7f [2] f1 }

  condition:
    any of them
}