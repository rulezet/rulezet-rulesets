rule TTP_XOR_MULT_DOSStub_9041 {
  strings:
    $key_9041 = { c4 29 [2] b0 31 [2] f7 33 [2] b0 22 [2] fe 2e [2] f2 24 [2] e5 2f [2] fe 61 [2] c3 }

  condition:
    any of them
}