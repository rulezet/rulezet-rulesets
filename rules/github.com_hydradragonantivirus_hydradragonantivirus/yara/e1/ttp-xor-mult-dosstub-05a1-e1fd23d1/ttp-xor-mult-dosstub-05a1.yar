rule TTP_XOR_MULT_DOSStub_05a1 {
  strings:
    $key_05a1 = { 51 c9 [2] 25 d1 [2] 62 d3 [2] 25 c2 [2] 6b ce [2] 67 c4 [2] 70 cf [2] 6b 81 [2] 56 }

  condition:
    any of them
}