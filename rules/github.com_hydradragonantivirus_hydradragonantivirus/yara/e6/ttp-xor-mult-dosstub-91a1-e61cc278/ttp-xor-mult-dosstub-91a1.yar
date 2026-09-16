rule TTP_XOR_MULT_DOSStub_91a1 {
  strings:
    $key_91a1 = { c5 c9 [2] b1 d1 [2] f6 d3 [2] b1 c2 [2] ff ce [2] f3 c4 [2] e4 cf [2] ff 81 [2] c2 }

  condition:
    any of them
}