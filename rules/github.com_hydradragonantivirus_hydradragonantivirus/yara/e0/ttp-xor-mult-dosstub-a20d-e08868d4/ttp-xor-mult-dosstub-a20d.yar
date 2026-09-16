rule TTP_XOR_MULT_DOSStub_a20d {
  strings:
    $key_a20d = { f6 65 [2] 82 7d [2] c5 7f [2] 82 6e [2] cc 62 [2] c0 68 [2] d7 63 [2] cc 2d [2] f1 }

  condition:
    any of them
}