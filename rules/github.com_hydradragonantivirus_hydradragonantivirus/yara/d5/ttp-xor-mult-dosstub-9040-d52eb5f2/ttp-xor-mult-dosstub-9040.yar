rule TTP_XOR_MULT_DOSStub_9040 {
  strings:
    $key_9040 = { c4 28 [2] b0 30 [2] f7 32 [2] b0 23 [2] fe 2f [2] f2 25 [2] e5 2e [2] fe 60 [2] c3 }

  condition:
    any of them
}