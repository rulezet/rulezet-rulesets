rule TTP_XOR_MULT_DOSStub_9035 {
  strings:
    $key_9035 = { c4 5d [2] b0 45 [2] f7 47 [2] b0 56 [2] fe 5a [2] f2 50 [2] e5 5b [2] fe 15 [2] c3 }

  condition:
    any of them
}