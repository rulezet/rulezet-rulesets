rule TTP_XOR_MULT_DOSStub_7ba0 {
  strings:
    $key_7ba0 = { 2f c8 [2] 5b d0 [2] 1c d2 [2] 5b c3 [2] 15 cf [2] 19 c5 [2] 0e ce [2] 15 80 [2] 28 }

  condition:
    any of them
}