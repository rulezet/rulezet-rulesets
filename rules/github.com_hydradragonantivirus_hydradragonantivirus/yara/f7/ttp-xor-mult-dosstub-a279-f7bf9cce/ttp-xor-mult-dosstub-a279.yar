rule TTP_XOR_MULT_DOSStub_a279 {
  strings:
    $key_a279 = { f6 11 [2] 82 09 [2] c5 0b [2] 82 1a [2] cc 16 [2] c0 1c [2] d7 17 [2] cc 59 [2] f1 }

  condition:
    any of them
}