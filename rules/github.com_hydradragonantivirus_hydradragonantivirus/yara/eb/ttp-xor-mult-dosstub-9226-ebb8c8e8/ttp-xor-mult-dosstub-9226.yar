rule TTP_XOR_MULT_DOSStub_9226 {
  strings:
    $key_9226 = { c6 4e [2] b2 56 [2] f5 54 [2] b2 45 [2] fc 49 [2] f0 43 [2] e7 48 [2] fc 06 [2] c1 }

  condition:
    any of them
}