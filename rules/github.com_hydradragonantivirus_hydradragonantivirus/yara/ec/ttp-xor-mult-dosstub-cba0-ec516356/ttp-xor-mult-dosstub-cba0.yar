rule TTP_XOR_MULT_DOSStub_cba0 {
  strings:
    $key_cba0 = { 9f c8 [2] eb d0 [2] ac d2 [2] eb c3 [2] a5 cf [2] a9 c5 [2] be ce [2] a5 80 [2] 98 }

  condition:
    any of them
}