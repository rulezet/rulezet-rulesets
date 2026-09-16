rule TTP_XOR_MULT_DOSStub_b7ac {
  strings:
    $key_b7ac = { e3 c4 [2] 97 dc [2] d0 de [2] 97 cf [2] d9 c3 [2] d5 c9 [2] c2 c2 [2] d9 8c [2] e4 }

  condition:
    any of them
}