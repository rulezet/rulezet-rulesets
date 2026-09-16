rule TTP_XOR_MULT_DOSStub_58ac {
  strings:
    $key_58ac = { 0c c4 [2] 78 dc [2] 3f de [2] 78 cf [2] 36 c3 [2] 3a c9 [2] 2d c2 [2] 36 8c [2] 0b }

  condition:
    any of them
}