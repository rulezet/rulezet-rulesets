rule TTP_XOR_MULT_DOSStub_5ba1 {
  strings:
    $key_5ba1 = { 0f c9 [2] 7b d1 [2] 3c d3 [2] 7b c2 [2] 35 ce [2] 39 c4 [2] 2e cf [2] 35 81 [2] 08 }

  condition:
    any of them
}