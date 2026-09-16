rule TTP_XOR_MULT_DOSStub_a266 {
  strings:
    $key_a266 = { f6 0e [2] 82 16 [2] c5 14 [2] 82 05 [2] cc 09 [2] c0 03 [2] d7 08 [2] cc 46 [2] f1 }

  condition:
    any of them
}