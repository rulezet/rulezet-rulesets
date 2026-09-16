rule TTP_XOR_MULT_DOSStub_9077 {
  strings:
    $key_9077 = { c4 1f [2] b0 07 [2] f7 05 [2] b0 14 [2] fe 18 [2] f2 12 [2] e5 19 [2] fe 57 [2] c3 }

  condition:
    any of them
}