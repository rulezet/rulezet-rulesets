rule TTP_XOR_MULT_DOSStub_9050 {
  strings:
    $key_9050 = { c4 38 [2] b0 20 [2] f7 22 [2] b0 33 [2] fe 3f [2] f2 35 [2] e5 3e [2] fe 70 [2] c3 }

  condition:
    any of them
}