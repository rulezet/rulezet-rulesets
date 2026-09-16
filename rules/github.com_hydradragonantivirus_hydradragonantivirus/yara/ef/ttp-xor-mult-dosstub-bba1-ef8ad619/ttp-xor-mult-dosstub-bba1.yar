rule TTP_XOR_MULT_DOSStub_bba1 {
  strings:
    $key_bba1 = { ef c9 [2] 9b d1 [2] dc d3 [2] 9b c2 [2] d5 ce [2] d9 c4 [2] ce cf [2] d5 81 [2] e8 }

  condition:
    any of them
}