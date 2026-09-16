rule TTP_XOR_MULT_DOSStub_a034 {
  strings:
    $key_a034 = { f4 5c [2] 80 44 [2] c7 46 [2] 80 57 [2] ce 5b [2] c2 51 [2] d5 5a [2] ce 14 [2] f3 }

  condition:
    any of them
}