rule TTP_XOR_MULT_DOSStub_5ea0 {
  strings:
    $key_5ea0 = { 0a c8 [2] 7e d0 [2] 39 d2 [2] 7e c3 [2] 30 cf [2] 3c c5 [2] 2b ce [2] 30 80 [2] 0d }

  condition:
    any of them
}