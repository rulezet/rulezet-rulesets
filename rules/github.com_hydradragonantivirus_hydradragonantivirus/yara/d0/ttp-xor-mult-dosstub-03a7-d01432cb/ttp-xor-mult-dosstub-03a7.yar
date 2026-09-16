rule TTP_XOR_MULT_DOSStub_03a7 {
  strings:
    $key_03a7 = { 57 cf [2] 23 d7 [2] 64 d5 [2] 23 c4 [2] 6d c8 [2] 61 c2 [2] 76 c9 [2] 6d 87 [2] 50 }

  condition:
    any of them
}