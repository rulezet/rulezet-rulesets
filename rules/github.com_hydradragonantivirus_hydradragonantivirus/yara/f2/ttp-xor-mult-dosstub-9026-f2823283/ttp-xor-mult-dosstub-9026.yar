rule TTP_XOR_MULT_DOSStub_9026 {
  strings:
    $key_9026 = { c4 4e [2] b0 56 [2] f7 54 [2] b0 45 [2] fe 49 [2] f2 43 [2] e5 48 [2] fe 06 [2] c3 }

  condition:
    any of them
}