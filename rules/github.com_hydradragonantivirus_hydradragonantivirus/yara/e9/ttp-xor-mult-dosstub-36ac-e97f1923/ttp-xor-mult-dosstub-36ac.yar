rule TTP_XOR_MULT_DOSStub_36ac {
  strings:
    $key_36ac = { 62 c4 [2] 16 dc [2] 51 de [2] 16 cf [2] 58 c3 [2] 54 c9 [2] 43 c2 [2] 58 8c [2] 65 }

  condition:
    any of them
}