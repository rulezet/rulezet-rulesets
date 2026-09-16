rule TTP_XOR_MULT_DOSStub_a2e8 {
  strings:
    $key_a2e8 = { f6 80 [2] 82 98 [2] c5 9a [2] 82 8b [2] cc 87 [2] c0 8d [2] d7 86 [2] cc c8 [2] f1 }

  condition:
    any of them
}