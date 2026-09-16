rule TTP_XOR_MULT_DOSStub_30ac {
  strings:
    $key_30ac = { 64 c4 [2] 10 dc [2] 57 de [2] 10 cf [2] 5e c3 [2] 52 c9 [2] 45 c2 [2] 5e 8c [2] 63 }

  condition:
    any of them
}