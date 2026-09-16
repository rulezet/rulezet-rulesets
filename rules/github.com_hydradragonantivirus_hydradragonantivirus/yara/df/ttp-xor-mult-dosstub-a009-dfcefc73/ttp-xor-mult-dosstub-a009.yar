rule TTP_XOR_MULT_DOSStub_a009 {
  strings:
    $key_a009 = { f4 61 [2] 80 79 [2] c7 7b [2] 80 6a [2] ce 66 [2] c2 6c [2] d5 67 [2] ce 29 [2] f3 }

  condition:
    any of them
}