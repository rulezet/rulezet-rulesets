rule TTP_XOR_MULT_DOSStub_9222 {
  strings:
    $key_9222 = { c6 4a [2] b2 52 [2] f5 50 [2] b2 41 [2] fc 4d [2] f0 47 [2] e7 4c [2] fc 02 [2] c1 }

  condition:
    any of them
}