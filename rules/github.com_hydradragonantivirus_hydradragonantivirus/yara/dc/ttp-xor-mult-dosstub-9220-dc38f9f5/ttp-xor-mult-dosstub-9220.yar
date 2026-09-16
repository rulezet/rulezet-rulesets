rule TTP_XOR_MULT_DOSStub_9220 {
  strings:
    $key_9220 = { c6 48 [2] b2 50 [2] f5 52 [2] b2 43 [2] fc 4f [2] f0 45 [2] e7 4e [2] fc 00 [2] c1 }

  condition:
    any of them
}