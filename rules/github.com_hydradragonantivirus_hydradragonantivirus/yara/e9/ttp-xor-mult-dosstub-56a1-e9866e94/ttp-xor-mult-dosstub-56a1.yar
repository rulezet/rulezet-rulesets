rule TTP_XOR_MULT_DOSStub_56a1 {
  strings:
    $key_56a1 = { 02 c9 [2] 76 d1 [2] 31 d3 [2] 76 c2 [2] 38 ce [2] 34 c4 [2] 23 cf [2] 38 81 [2] 05 }

  condition:
    any of them
}