rule TTP_XOR_MULT_DOSStub_a21b {
  strings:
    $key_a21b = { f6 73 [2] 82 6b [2] c5 69 [2] 82 78 [2] cc 74 [2] c0 7e [2] d7 75 [2] cc 3b [2] f1 }

  condition:
    any of them
}