rule TTP_XOR_MULT_DOSStub_9797 {
  strings:
    $key_9797 = { c3 ff [2] b7 e7 [2] f0 e5 [2] b7 f4 [2] f9 f8 [2] f5 f2 [2] e2 f9 [2] f9 b7 [2] c4 }

  condition:
    any of them
}