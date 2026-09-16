rule TTP_XOR_MULT_DOSStub_9628 {
  strings:
    $key_9628 = { c2 40 [2] b6 58 [2] f1 5a [2] b6 4b [2] f8 47 [2] f4 4d [2] e3 46 [2] f8 08 [2] c5 }

  condition:
    any of them
}