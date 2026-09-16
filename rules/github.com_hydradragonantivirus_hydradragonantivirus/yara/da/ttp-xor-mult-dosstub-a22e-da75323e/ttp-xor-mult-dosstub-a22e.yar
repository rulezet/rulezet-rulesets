rule TTP_XOR_MULT_DOSStub_a22e {
  strings:
    $key_a22e = { f6 46 [2] 82 5e [2] c5 5c [2] 82 4d [2] cc 41 [2] c0 4b [2] d7 40 [2] cc 0e [2] f1 }

  condition:
    any of them
}