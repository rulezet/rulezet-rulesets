rule TTP_XOR_MULT_DOSStub_6ea7 {
  strings:
    $key_6ea7 = { 3a cf [2] 4e d7 [2] 09 d5 [2] 4e c4 [2] 00 c8 [2] 0c c2 [2] 1b c9 [2] 00 87 [2] 3d }

  condition:
    any of them
}