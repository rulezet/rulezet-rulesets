rule TTP_XOR_MULT_DOSStub_9033 {
  strings:
    $key_9033 = { c4 5b [2] b0 43 [2] f7 41 [2] b0 50 [2] fe 5c [2] f2 56 [2] e5 5d [2] fe 13 [2] c3 }

  condition:
    any of them
}