rule TTP_XOR_MULT_DOSStub_96e3 {
  strings:
    $key_96e3 = { c2 8b [2] b6 93 [2] f1 91 [2] b6 80 [2] f8 8c [2] f4 86 [2] e3 8d [2] f8 c3 [2] c5 }

  condition:
    any of them
}