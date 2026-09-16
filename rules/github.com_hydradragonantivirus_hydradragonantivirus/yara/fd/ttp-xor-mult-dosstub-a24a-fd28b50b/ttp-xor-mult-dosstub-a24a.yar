rule TTP_XOR_MULT_DOSStub_a24a {
  strings:
    $key_a24a = { f6 22 [2] 82 3a [2] c5 38 [2] 82 29 [2] cc 25 [2] c0 2f [2] d7 24 [2] cc 6a [2] f1 }

  condition:
    any of them
}