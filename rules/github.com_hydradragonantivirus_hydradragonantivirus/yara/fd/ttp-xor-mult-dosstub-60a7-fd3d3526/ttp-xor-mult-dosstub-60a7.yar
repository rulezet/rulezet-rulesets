rule TTP_XOR_MULT_DOSStub_60a7 {
  strings:
    $key_60a7 = { 34 cf [2] 40 d7 [2] 07 d5 [2] 40 c4 [2] 0e c8 [2] 02 c2 [2] 15 c9 [2] 0e 87 [2] 33 }

  condition:
    any of them
}