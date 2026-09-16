rule TTP_XOR_MULT_DOSStub_51a1 {
  strings:
    $key_51a1 = { 05 c9 [2] 71 d1 [2] 36 d3 [2] 71 c2 [2] 3f ce [2] 33 c4 [2] 24 cf [2] 3f 81 [2] 02 }

  condition:
    any of them
}