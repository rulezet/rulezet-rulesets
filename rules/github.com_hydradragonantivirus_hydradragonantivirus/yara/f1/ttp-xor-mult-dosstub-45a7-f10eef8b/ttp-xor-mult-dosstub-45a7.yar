rule TTP_XOR_MULT_DOSStub_45a7 {
  strings:
    $key_45a7 = { 11 cf [2] 65 d7 [2] 22 d5 [2] 65 c4 [2] 2b c8 [2] 27 c2 [2] 30 c9 [2] 2b 87 [2] 16 }

  condition:
    any of them
}