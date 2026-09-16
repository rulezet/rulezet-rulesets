rule TTP_XOR_MULT_DOSStub_25a1 {
  strings:
    $key_25a1 = { 71 c9 [2] 05 d1 [2] 42 d3 [2] 05 c2 [2] 4b ce [2] 47 c4 [2] 50 cf [2] 4b 81 [2] 76 }

  condition:
    any of them
}