rule TTP_XOR_MULT_DOSStub_e0a7 {
  strings:
    $key_e0a7 = { b4 cf [2] c0 d7 [2] 87 d5 [2] c0 c4 [2] 8e c8 [2] 82 c2 [2] 95 c9 [2] 8e 87 [2] b3 }

  condition:
    any of them
}