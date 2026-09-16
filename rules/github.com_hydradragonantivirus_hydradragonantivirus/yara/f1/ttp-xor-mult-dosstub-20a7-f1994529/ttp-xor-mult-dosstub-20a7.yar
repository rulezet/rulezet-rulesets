rule TTP_XOR_MULT_DOSStub_20a7 {
  strings:
    $key_20a7 = { 74 cf [2] 00 d7 [2] 47 d5 [2] 00 c4 [2] 4e c8 [2] 42 c2 [2] 55 c9 [2] 4e 87 [2] 73 }

  condition:
    any of them
}