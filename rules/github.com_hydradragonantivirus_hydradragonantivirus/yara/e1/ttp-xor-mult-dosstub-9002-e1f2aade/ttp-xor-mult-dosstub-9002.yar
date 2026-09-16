rule TTP_XOR_MULT_DOSStub_9002 {
  strings:
    $key_9002 = { c4 6a [2] b0 72 [2] f7 70 [2] b0 61 [2] fe 6d [2] f2 67 [2] e5 6c [2] fe 22 [2] c3 }

  condition:
    any of them
}