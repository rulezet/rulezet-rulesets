rule TTP_XOR_MULT_DOSStub_9533 {
  strings:
    $key_9533 = { c1 5b [2] b5 43 [2] f2 41 [2] b5 50 [2] fb 5c [2] f7 56 [2] e0 5d [2] fb 13 [2] c6 }

  condition:
    any of them
}