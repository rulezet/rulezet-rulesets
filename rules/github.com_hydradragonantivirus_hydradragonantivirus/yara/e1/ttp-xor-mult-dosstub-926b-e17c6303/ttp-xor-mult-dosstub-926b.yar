rule TTP_XOR_MULT_DOSStub_926b {
  strings:
    $key_926b = { c6 03 [2] b2 1b [2] f5 19 [2] b2 08 [2] fc 04 [2] f0 0e [2] e7 05 [2] fc 4b [2] c1 }

  condition:
    any of them
}