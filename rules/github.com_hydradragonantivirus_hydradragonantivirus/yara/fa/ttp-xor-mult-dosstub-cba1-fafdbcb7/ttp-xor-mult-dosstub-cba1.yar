rule TTP_XOR_MULT_DOSStub_cba1 {
  strings:
    $key_cba1 = { 9f c9 [2] eb d1 [2] ac d3 [2] eb c2 [2] a5 ce [2] a9 c4 [2] be cf [2] a5 81 [2] 98 }

  condition:
    any of them
}