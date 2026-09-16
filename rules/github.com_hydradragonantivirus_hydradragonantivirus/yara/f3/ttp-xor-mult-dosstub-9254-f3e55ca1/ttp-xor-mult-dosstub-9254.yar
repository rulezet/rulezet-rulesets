rule TTP_XOR_MULT_DOSStub_9254 {
  strings:
    $key_9254 = { c6 3c [2] b2 24 [2] f5 26 [2] b2 37 [2] fc 3b [2] f0 31 [2] e7 3a [2] fc 74 [2] c1 }

  condition:
    any of them
}