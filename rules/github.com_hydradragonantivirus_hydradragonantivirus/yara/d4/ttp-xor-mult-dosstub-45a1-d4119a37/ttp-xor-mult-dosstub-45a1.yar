rule TTP_XOR_MULT_DOSStub_45a1 {
  strings:
    $key_45a1 = { 11 c9 [2] 65 d1 [2] 22 d3 [2] 65 c2 [2] 2b ce [2] 27 c4 [2] 30 cf [2] 2b 81 [2] 16 }

  condition:
    any of them
}