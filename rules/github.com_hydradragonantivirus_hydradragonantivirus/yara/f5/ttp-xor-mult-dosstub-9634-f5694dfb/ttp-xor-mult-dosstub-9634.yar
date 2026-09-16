rule TTP_XOR_MULT_DOSStub_9634 {
  strings:
    $key_9634 = { c2 5c [2] b6 44 [2] f1 46 [2] b6 57 [2] f8 5b [2] f4 51 [2] e3 5a [2] f8 14 [2] c5 }

  condition:
    any of them
}