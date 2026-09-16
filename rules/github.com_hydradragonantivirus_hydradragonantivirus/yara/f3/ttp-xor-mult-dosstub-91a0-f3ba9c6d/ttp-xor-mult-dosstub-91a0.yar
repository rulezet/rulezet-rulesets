rule TTP_XOR_MULT_DOSStub_91a0 {
  strings:
    $key_91a0 = { c5 c8 [2] b1 d0 [2] f6 d2 [2] b1 c3 [2] ff cf [2] f3 c5 [2] e4 ce [2] ff 80 [2] c2 }

  condition:
    any of them
}