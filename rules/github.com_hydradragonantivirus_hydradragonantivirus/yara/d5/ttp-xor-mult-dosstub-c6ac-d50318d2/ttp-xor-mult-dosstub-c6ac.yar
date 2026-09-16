rule TTP_XOR_MULT_DOSStub_c6ac {
  strings:
    $key_c6ac = { 92 c4 [2] e6 dc [2] a1 de [2] e6 cf [2] a8 c3 [2] a4 c9 [2] b3 c2 [2] a8 8c [2] 95 }

  condition:
    any of them
}