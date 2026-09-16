rule TTP_XOR_MULT_DOSStub_9017 {
  strings:
    $key_9017 = { c4 7f [2] b0 67 [2] f7 65 [2] b0 74 [2] fe 78 [2] f2 72 [2] e5 79 [2] fe 37 [2] c3 }

  condition:
    any of them
}