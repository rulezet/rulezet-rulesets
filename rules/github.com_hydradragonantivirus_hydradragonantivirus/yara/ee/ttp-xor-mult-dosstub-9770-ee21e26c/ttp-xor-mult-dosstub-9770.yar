rule TTP_XOR_MULT_DOSStub_9770 {
  strings:
    $key_9770 = { c3 18 [2] b7 00 [2] f0 02 [2] b7 13 [2] f9 1f [2] f5 15 [2] e2 1e [2] f9 50 [2] c4 }

  condition:
    any of them
}