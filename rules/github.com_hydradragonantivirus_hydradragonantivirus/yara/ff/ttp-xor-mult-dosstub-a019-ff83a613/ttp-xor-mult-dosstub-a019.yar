rule TTP_XOR_MULT_DOSStub_a019 {
  strings:
    $key_a019 = { f4 71 [2] 80 69 [2] c7 6b [2] 80 7a [2] ce 76 [2] c2 7c [2] d5 77 [2] ce 39 [2] f3 }

  condition:
    any of them
}