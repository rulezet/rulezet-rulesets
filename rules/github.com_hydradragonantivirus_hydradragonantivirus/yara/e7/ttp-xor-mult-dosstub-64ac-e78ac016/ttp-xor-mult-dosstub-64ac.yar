rule TTP_XOR_MULT_DOSStub_64ac {
  strings:
    $key_64ac = { 30 c4 [2] 44 dc [2] 03 de [2] 44 cf [2] 0a c3 [2] 06 c9 [2] 11 c2 [2] 0a 8c [2] 37 }

  condition:
    any of them
}