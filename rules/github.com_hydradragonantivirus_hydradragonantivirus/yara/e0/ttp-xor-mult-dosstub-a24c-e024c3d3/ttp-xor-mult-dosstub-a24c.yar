rule TTP_XOR_MULT_DOSStub_a24c {
  strings:
    $key_a24c = { f6 24 [2] 82 3c [2] c5 3e [2] 82 2f [2] cc 23 [2] c0 29 [2] d7 22 [2] cc 6c [2] f1 }

  condition:
    any of them
}