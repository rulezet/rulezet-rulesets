rule TTP_XOR_MULT_DOSStub_9252 {
  strings:
    $key_9252 = { c6 3a [2] b2 22 [2] f5 20 [2] b2 31 [2] fc 3d [2] f0 37 [2] e7 3c [2] fc 72 [2] c1 }

  condition:
    any of them
}