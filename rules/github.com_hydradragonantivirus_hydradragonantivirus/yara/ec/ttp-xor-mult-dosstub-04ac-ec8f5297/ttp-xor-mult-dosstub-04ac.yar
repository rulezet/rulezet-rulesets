rule TTP_XOR_MULT_DOSStub_04ac {
  strings:
    $key_04ac = { 50 c4 [2] 24 dc [2] 63 de [2] 24 cf [2] 6a c3 [2] 66 c9 [2] 71 c2 [2] 6a 8c [2] 57 }

  condition:
    any of them
}