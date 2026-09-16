rule TTP_XOR_MULT_DOSStub_09ac {
  strings:
    $key_09ac = { 5d c4 [2] 29 dc [2] 6e de [2] 29 cf [2] 67 c3 [2] 6b c9 [2] 7c c2 [2] 67 8c [2] 5a }

  condition:
    any of them
}