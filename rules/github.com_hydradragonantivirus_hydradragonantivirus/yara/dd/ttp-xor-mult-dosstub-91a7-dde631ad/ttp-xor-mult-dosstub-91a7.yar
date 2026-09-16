rule TTP_XOR_MULT_DOSStub_91a7 {
  strings:
    $key_91a7 = { c5 cf [2] b1 d7 [2] f6 d5 [2] b1 c4 [2] ff c8 [2] f3 c2 [2] e4 c9 [2] ff 87 [2] c2 }

  condition:
    any of them
}