rule TTP_XOR_MULT_DOSStub_a733 {
  strings:
    $key_a733 = { f3 5b [2] 87 43 [2] c0 41 [2] 87 50 [2] c9 5c [2] c5 56 [2] d2 5d [2] c9 13 [2] f4 }

  condition:
    any of them
}