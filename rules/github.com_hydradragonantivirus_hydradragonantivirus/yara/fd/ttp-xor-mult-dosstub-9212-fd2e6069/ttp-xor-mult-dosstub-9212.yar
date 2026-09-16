rule TTP_XOR_MULT_DOSStub_9212 {
  strings:
    $key_9212 = { c6 7a [2] b2 62 [2] f5 60 [2] b2 71 [2] fc 7d [2] f0 77 [2] e7 7c [2] fc 32 [2] c1 }

  condition:
    any of them
}