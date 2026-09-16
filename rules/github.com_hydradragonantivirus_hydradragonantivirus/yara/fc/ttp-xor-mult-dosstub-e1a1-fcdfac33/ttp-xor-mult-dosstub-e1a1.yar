rule TTP_XOR_MULT_DOSStub_e1a1 {
  strings:
    $key_e1a1 = { b5 c9 [2] c1 d1 [2] 86 d3 [2] c1 c2 [2] 8f ce [2] 83 c4 [2] 94 cf [2] 8f 81 [2] b2 }

  condition:
    any of them
}