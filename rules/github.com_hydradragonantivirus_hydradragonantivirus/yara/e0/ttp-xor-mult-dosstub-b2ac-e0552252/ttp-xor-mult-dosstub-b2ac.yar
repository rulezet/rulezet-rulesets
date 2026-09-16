rule TTP_XOR_MULT_DOSStub_b2ac {
  strings:
    $key_b2ac = { e6 c4 [2] 92 dc [2] d5 de [2] 92 cf [2] dc c3 [2] d0 c9 [2] c7 c2 [2] dc 8c [2] e1 }

  condition:
    any of them
}