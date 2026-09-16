rule TTP_XOR_MULT_DOSStub_a008 {
  strings:
    $key_a008 = { f4 60 [2] 80 78 [2] c7 7a [2] 80 6b [2] ce 67 [2] c2 6d [2] d5 66 [2] ce 28 [2] f3 }

  condition:
    any of them
}