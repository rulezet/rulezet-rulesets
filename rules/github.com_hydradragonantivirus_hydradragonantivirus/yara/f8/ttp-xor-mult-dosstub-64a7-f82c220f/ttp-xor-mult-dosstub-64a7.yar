rule TTP_XOR_MULT_DOSStub_64a7 {
  strings:
    $key_64a7 = { 30 cf [2] 44 d7 [2] 03 d5 [2] 44 c4 [2] 0a c8 [2] 06 c2 [2] 11 c9 [2] 0a 87 [2] 37 }

  condition:
    any of them
}