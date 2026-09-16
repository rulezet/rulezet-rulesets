rule TTP_XOR_MULT_DOSStub_a2e0 {
  strings:
    $key_a2e0 = { f6 88 [2] 82 90 [2] c5 92 [2] 82 83 [2] cc 8f [2] c0 85 [2] d7 8e [2] cc c0 [2] f1 }

  condition:
    any of them
}