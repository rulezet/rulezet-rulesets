rule TTP_XOR_MULT_DOSStub_a0e4 {
  strings:
    $key_a0e4 = { f4 8c [2] 80 94 [2] c7 96 [2] 80 87 [2] ce 8b [2] c2 81 [2] d5 8a [2] ce c4 [2] f3 }

  condition:
    any of them
}