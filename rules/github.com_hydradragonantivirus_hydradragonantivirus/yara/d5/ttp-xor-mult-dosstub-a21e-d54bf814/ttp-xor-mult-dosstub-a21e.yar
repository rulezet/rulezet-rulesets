rule TTP_XOR_MULT_DOSStub_a21e {
  strings:
    $key_a21e = { f6 76 [2] 82 6e [2] c5 6c [2] 82 7d [2] cc 71 [2] c0 7b [2] d7 70 [2] cc 3e [2] f1 }

  condition:
    any of them
}