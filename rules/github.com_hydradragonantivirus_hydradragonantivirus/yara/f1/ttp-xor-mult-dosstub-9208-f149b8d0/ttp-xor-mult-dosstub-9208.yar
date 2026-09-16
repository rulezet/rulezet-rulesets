rule TTP_XOR_MULT_DOSStub_9208 {
  strings:
    $key_9208 = { c6 60 [2] b2 78 [2] f5 7a [2] b2 6b [2] fc 67 [2] f0 6d [2] e7 66 [2] fc 28 [2] c1 }

  condition:
    any of them
}