rule TTP_XOR_MULT_DOSStub_9246 {
  strings:
    $key_9246 = { c6 2e [2] b2 36 [2] f5 34 [2] b2 25 [2] fc 29 [2] f0 23 [2] e7 28 [2] fc 66 [2] c1 }

  condition:
    any of them
}