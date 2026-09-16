rule TTP_XOR_MULT_DOSStub_9217 {
  strings:
    $key_9217 = { c6 7f [2] b2 67 [2] f5 65 [2] b2 74 [2] fc 78 [2] f0 72 [2] e7 79 [2] fc 37 [2] c1 }

  condition:
    any of them
}