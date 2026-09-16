rule TTP_XOR_MULT_DOSStub_9297 {
  strings:
    $key_9297 = { c6 ff [2] b2 e7 [2] f5 e5 [2] b2 f4 [2] fc f8 [2] f0 f2 [2] e7 f9 [2] fc b7 [2] c1 }

  condition:
    any of them
}