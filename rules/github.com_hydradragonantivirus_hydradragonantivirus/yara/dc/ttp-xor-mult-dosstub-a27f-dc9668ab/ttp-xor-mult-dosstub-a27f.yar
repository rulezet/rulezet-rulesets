rule TTP_XOR_MULT_DOSStub_a27f {
  strings:
    $key_a27f = { f6 17 [2] 82 0f [2] c5 0d [2] 82 1c [2] cc 10 [2] c0 1a [2] d7 11 [2] cc 5f [2] f1 }

  condition:
    any of them
}