rule TTP_XOR_MULT_DOSStub_e6a7 {
  strings:
    $key_e6a7 = { b2 cf [2] c6 d7 [2] 81 d5 [2] c6 c4 [2] 88 c8 [2] 84 c2 [2] 93 c9 [2] 88 87 [2] b5 }

  condition:
    any of them
}