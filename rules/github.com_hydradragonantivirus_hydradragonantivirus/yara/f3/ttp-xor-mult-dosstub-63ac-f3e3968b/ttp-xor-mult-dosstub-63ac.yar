rule TTP_XOR_MULT_DOSStub_63ac {
  strings:
    $key_63ac = { 37 c4 [2] 43 dc [2] 04 de [2] 43 cf [2] 0d c3 [2] 01 c9 [2] 16 c2 [2] 0d 8c [2] 30 }

  condition:
    any of them
}