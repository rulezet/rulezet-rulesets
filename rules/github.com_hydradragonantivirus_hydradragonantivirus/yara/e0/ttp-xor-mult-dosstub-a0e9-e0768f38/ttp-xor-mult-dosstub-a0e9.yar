rule TTP_XOR_MULT_DOSStub_a0e9 {
  strings:
    $key_a0e9 = { f4 81 [2] 80 99 [2] c7 9b [2] 80 8a [2] ce 86 [2] c2 8c [2] d5 87 [2] ce c9 [2] f3 }

  condition:
    any of them
}