rule TTP_XOR_MULT_DOSStub_a206 {
  strings:
    $key_a206 = { f6 6e [2] 82 76 [2] c5 74 [2] 82 65 [2] cc 69 [2] c0 63 [2] d7 68 [2] cc 26 [2] f1 }

  condition:
    any of them
}