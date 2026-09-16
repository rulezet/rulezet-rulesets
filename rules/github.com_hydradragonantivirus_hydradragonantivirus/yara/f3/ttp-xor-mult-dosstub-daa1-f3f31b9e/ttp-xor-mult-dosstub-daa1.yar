rule TTP_XOR_MULT_DOSStub_daa1 {
  strings:
    $key_daa1 = { 8e c9 [2] fa d1 [2] bd d3 [2] fa c2 [2] b4 ce [2] b8 c4 [2] af cf [2] b4 81 [2] 89 }

  condition:
    any of them
}