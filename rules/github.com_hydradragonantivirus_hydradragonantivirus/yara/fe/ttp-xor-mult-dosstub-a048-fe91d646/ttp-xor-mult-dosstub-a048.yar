rule TTP_XOR_MULT_DOSStub_a048 {
  strings:
    $key_a048 = { f4 20 [2] 80 38 [2] c7 3a [2] 80 2b [2] ce 27 [2] c2 2d [2] d5 26 [2] ce 68 [2] f3 }

  condition:
    any of them
}