rule TTP_XOR_MULT_DOSStub_42a7 {
  strings:
    $key_42a7 = { 16 cf [2] 62 d7 [2] 25 d5 [2] 62 c4 [2] 2c c8 [2] 20 c2 [2] 37 c9 [2] 2c 87 [2] 11 }

  condition:
    any of them
}