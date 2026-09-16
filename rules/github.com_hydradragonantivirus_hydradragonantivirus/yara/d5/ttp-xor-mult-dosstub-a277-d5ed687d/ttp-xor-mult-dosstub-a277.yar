rule TTP_XOR_MULT_DOSStub_a277 {
  strings:
    $key_a277 = { f6 1f [2] 82 07 [2] c5 05 [2] 82 14 [2] cc 18 [2] c0 12 [2] d7 19 [2] cc 57 [2] f1 }

  condition:
    any of them
}