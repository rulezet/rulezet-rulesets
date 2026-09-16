rule TTP_XOR_MULT_DOSStub_a25d {
  strings:
    $key_a25d = { f6 35 [2] 82 2d [2] c5 2f [2] 82 3e [2] cc 32 [2] c0 38 [2] d7 33 [2] cc 7d [2] f1 }

  condition:
    any of them
}