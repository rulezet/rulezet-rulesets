rule TTP_XOR_MULT_DOSStub_927f {
  strings:
    $key_927f = { c6 17 [2] b2 0f [2] f5 0d [2] b2 1c [2] fc 10 [2] f0 1a [2] e7 11 [2] fc 5f [2] c1 }

  condition:
    any of them
}