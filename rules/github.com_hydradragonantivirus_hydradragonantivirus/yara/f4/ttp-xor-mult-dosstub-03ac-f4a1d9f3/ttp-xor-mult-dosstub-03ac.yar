rule TTP_XOR_MULT_DOSStub_03ac {
  strings:
    $key_03ac = { 57 c4 [2] 23 dc [2] 64 de [2] 23 cf [2] 6d c3 [2] 61 c9 [2] 76 c2 [2] 6d 8c [2] 50 }

  condition:
    any of them
}