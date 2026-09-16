rule TTP_XOR_MULT_DOSStub_c8ac {
  strings:
    $key_c8ac = { 9c c4 [2] e8 dc [2] af de [2] e8 cf [2] a6 c3 [2] aa c9 [2] bd c2 [2] a6 8c [2] 9b }

  condition:
    any of them
}