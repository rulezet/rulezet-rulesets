rule TTP_XOR_MULT_DOSStub_6ea0 {
  strings:
    $key_6ea0 = { 3a c8 [2] 4e d0 [2] 09 d2 [2] 4e c3 [2] 00 cf [2] 0c c5 [2] 1b ce [2] 00 80 [2] 3d }

  condition:
    any of them
}