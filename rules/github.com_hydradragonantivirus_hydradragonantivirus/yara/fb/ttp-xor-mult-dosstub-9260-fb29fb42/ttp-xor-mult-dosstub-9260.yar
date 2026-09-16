rule TTP_XOR_MULT_DOSStub_9260 {
  strings:
    $key_9260 = { c6 08 [2] b2 10 [2] f5 12 [2] b2 03 [2] fc 0f [2] f0 05 [2] e7 0e [2] fc 40 [2] c1 }

  condition:
    any of them
}