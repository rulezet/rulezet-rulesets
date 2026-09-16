rule TTP_XOR_MULT_DOSStub_5ba0 {
  strings:
    $key_5ba0 = { 0f c8 [2] 7b d0 [2] 3c d2 [2] 7b c3 [2] 35 cf [2] 39 c5 [2] 2e ce [2] 35 80 [2] 08 }

  condition:
    any of them
}