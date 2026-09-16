rule TTP_XOR_MULT_DOSStub_06ac {
  strings:
    $key_06ac = { 52 c4 [2] 26 dc [2] 61 de [2] 26 cf [2] 68 c3 [2] 64 c9 [2] 73 c2 [2] 68 8c [2] 55 }

  condition:
    any of them
}