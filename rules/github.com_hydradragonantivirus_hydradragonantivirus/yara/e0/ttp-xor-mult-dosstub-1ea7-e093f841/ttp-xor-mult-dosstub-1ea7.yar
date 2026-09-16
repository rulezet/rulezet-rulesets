rule TTP_XOR_MULT_DOSStub_1ea7 {
  strings:
    $key_1ea7 = { 4a cf [2] 3e d7 [2] 79 d5 [2] 3e c4 [2] 70 c8 [2] 7c c2 [2] 6b c9 [2] 70 87 [2] 4d }

  condition:
    any of them
}