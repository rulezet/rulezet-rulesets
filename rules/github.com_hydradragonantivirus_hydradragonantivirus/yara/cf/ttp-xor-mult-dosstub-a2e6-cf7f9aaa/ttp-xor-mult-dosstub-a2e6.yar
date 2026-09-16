rule TTP_XOR_MULT_DOSStub_a2e6 {
  strings:
    $key_a2e6 = { f6 8e [2] 82 96 [2] c5 94 [2] 82 85 [2] cc 89 [2] c0 83 [2] d7 88 [2] cc c6 [2] f1 }

  condition:
    any of them
}