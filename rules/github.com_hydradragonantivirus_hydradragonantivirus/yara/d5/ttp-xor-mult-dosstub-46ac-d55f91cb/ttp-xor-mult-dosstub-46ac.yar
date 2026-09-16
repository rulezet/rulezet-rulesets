rule TTP_XOR_MULT_DOSStub_46ac {
  strings:
    $key_46ac = { 12 c4 [2] 66 dc [2] 21 de [2] 66 cf [2] 28 c3 [2] 24 c9 [2] 33 c2 [2] 28 8c [2] 15 }

  condition:
    any of them
}