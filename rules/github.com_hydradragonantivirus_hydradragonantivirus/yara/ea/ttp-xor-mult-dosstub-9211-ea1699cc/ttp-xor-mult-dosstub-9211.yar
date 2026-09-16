rule TTP_XOR_MULT_DOSStub_9211 {
  strings:
    $key_9211 = { c6 79 [2] b2 61 [2] f5 63 [2] b2 72 [2] fc 7e [2] f0 74 [2] e7 7f [2] fc 31 [2] c1 }

  condition:
    any of them
}