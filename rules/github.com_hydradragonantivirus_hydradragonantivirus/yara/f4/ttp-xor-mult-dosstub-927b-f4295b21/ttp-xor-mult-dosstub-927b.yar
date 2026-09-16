rule TTP_XOR_MULT_DOSStub_927b {
  strings:
    $key_927b = { c6 13 [2] b2 0b [2] f5 09 [2] b2 18 [2] fc 14 [2] f0 1e [2] e7 15 [2] fc 5b [2] c1 }

  condition:
    any of them
}