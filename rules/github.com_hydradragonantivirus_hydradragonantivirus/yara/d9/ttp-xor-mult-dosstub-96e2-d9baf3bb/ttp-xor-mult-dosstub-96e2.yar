rule TTP_XOR_MULT_DOSStub_96e2 {
  strings:
    $key_96e2 = { c2 8a [2] b6 92 [2] f1 90 [2] b6 81 [2] f8 8d [2] f4 87 [2] e3 8c [2] f8 c2 [2] c5 }

  condition:
    any of them
}