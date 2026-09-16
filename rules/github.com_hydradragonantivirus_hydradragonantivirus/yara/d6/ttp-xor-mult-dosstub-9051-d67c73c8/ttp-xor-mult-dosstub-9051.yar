rule TTP_XOR_MULT_DOSStub_9051 {
  strings:
    $key_9051 = { c4 39 [2] b0 21 [2] f7 23 [2] b0 32 [2] fe 3e [2] f2 34 [2] e5 3f [2] fe 71 [2] c3 }

  condition:
    any of them
}