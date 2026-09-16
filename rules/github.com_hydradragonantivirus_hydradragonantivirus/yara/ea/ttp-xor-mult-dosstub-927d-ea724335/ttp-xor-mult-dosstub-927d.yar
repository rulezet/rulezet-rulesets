rule TTP_XOR_MULT_DOSStub_927d {
  strings:
    $key_927d = { c6 15 [2] b2 0d [2] f5 0f [2] b2 1e [2] fc 12 [2] f0 18 [2] e7 13 [2] fc 5d [2] c1 }

  condition:
    any of them
}