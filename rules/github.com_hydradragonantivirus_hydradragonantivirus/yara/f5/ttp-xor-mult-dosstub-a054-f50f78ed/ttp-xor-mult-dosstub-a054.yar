rule TTP_XOR_MULT_DOSStub_a054 {
  strings:
    $key_a054 = { f4 3c [2] 80 24 [2] c7 26 [2] 80 37 [2] ce 3b [2] c2 31 [2] d5 3a [2] ce 74 [2] f3 }

  condition:
    any of them
}