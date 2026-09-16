rule TTP_XOR_MULT_DOSStub_96f3 {
  strings:
    $key_96f3 = { c2 9b [2] b6 83 [2] f1 81 [2] b6 90 [2] f8 9c [2] f4 96 [2] e3 9d [2] f8 d3 [2] c5 }

  condition:
    any of them
}