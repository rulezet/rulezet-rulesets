rule TTP_XOR_MULT_DOSStub_55a7 {
  strings:
    $key_55a7 = { 01 cf [2] 75 d7 [2] 32 d5 [2] 75 c4 [2] 3b c8 [2] 37 c2 [2] 20 c9 [2] 3b 87 [2] 06 }

  condition:
    any of them
}