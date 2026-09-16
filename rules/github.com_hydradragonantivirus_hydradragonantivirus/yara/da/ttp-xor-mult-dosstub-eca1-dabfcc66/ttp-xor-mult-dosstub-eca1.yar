rule TTP_XOR_MULT_DOSStub_eca1 {
  strings:
    $key_eca1 = { b8 c9 [2] cc d1 [2] 8b d3 [2] cc c2 [2] 82 ce [2] 8e c4 [2] 99 cf [2] 82 81 [2] bf }

  condition:
    any of them
}