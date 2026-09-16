rule TTP_XOR_MULT_DOSStub_73ac {
  strings:
    $key_73ac = { 27 c4 [2] 53 dc [2] 14 de [2] 53 cf [2] 1d c3 [2] 11 c9 [2] 06 c2 [2] 1d 8c [2] 20 }

  condition:
    any of them
}