rule TTP_XOR_MULT_DOSStub_a2ef {
  strings:
    $key_a2ef = { f6 87 [2] 82 9f [2] c5 9d [2] 82 8c [2] cc 80 [2] c0 8a [2] d7 81 [2] cc cf [2] f1 }

  condition:
    any of them
}