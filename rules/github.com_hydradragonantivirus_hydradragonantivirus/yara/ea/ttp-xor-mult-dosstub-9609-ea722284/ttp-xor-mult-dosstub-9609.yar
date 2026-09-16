rule TTP_XOR_MULT_DOSStub_9609 {
  strings:
    $key_9609 = { c2 61 [2] b6 79 [2] f1 7b [2] b6 6a [2] f8 66 [2] f4 6c [2] e3 67 [2] f8 29 [2] c5 }

  condition:
    any of them
}