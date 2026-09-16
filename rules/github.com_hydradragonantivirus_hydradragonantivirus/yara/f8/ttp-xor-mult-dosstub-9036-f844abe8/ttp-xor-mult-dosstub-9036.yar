rule TTP_XOR_MULT_DOSStub_9036 {
  strings:
    $key_9036 = { c4 5e [2] b0 46 [2] f7 44 [2] b0 55 [2] fe 59 [2] f2 53 [2] e5 58 [2] fe 16 [2] c3 }

  condition:
    any of them
}