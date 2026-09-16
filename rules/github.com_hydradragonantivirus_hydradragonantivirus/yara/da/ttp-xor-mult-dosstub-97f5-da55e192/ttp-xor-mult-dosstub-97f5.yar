rule TTP_XOR_MULT_DOSStub_97f5 {
  strings:
    $key_97f5 = { c3 9d [2] b7 85 [2] f0 87 [2] b7 96 [2] f9 9a [2] f5 90 [2] e2 9b [2] f9 d5 [2] c4 }

  condition:
    any of them
}