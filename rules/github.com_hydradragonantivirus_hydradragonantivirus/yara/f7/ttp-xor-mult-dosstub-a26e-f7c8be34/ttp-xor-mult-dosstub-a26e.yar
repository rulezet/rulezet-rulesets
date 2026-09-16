rule TTP_XOR_MULT_DOSStub_a26e {
  strings:
    $key_a26e = { f6 06 [2] 82 1e [2] c5 1c [2] 82 0d [2] cc 01 [2] c0 0b [2] d7 00 [2] cc 4e [2] f1 }

  condition:
    any of them
}