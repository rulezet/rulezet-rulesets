rule TTP_XOR_MULT_DOSStub_79ac {
  strings:
    $key_79ac = { 2d c4 [2] 59 dc [2] 1e de [2] 59 cf [2] 17 c3 [2] 1b c9 [2] 0c c2 [2] 17 8c [2] 2a }

  condition:
    any of them
}