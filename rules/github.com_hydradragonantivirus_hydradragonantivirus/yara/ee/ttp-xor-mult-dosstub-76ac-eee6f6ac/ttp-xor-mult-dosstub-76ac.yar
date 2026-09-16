rule TTP_XOR_MULT_DOSStub_76ac {
  strings:
    $key_76ac = { 22 c4 [2] 56 dc [2] 11 de [2] 56 cf [2] 18 c3 [2] 14 c9 [2] 03 c2 [2] 18 8c [2] 25 }

  condition:
    any of them
}