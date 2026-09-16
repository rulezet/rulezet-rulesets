rule TTP_XOR_MULT_DOSStub_aba1 {
  strings:
    $key_aba1 = { ff c9 [2] 8b d1 [2] cc d3 [2] 8b c2 [2] c5 ce [2] c9 c4 [2] de cf [2] c5 81 [2] f8 }

  condition:
    any of them
}