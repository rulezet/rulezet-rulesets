rule TTP_XOR_MULT_DOSStub_9022 {
  strings:
    $key_9022 = { c4 4a [2] b0 52 [2] f7 50 [2] b0 41 [2] fe 4d [2] f2 47 [2] e5 4c [2] fe 02 [2] c3 }

  condition:
    any of them
}