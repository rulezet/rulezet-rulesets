rule TTP_XOR_MULT_DOSStub_69a7 {
  strings:
    $key_69a7 = { 3d cf [2] 49 d7 [2] 0e d5 [2] 49 c4 [2] 07 c8 [2] 0b c2 [2] 1c c9 [2] 07 87 [2] 3a }

  condition:
    any of them
}