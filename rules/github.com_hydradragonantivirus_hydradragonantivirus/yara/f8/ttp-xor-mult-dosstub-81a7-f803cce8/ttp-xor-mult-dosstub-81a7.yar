rule TTP_XOR_MULT_DOSStub_81a7 {
  strings:
    $key_81a7 = { d5 cf [2] a1 d7 [2] e6 d5 [2] a1 c4 [2] ef c8 [2] e3 c2 [2] f4 c9 [2] ef 87 [2] d2 }

  condition:
    any of them
}