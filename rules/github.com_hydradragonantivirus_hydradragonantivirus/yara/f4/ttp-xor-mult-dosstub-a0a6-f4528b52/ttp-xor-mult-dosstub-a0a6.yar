rule TTP_XOR_MULT_DOSStub_a0a6 {
  strings:
    $key_a0a6 = { f4 ce [2] 80 d6 [2] c7 d4 [2] 80 c5 [2] ce c9 [2] c2 c3 [2] d5 c8 [2] ce 86 [2] f3 }

  condition:
    any of them
}