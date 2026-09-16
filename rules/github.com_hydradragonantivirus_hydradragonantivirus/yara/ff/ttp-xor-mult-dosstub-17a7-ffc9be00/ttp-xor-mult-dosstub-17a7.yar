rule TTP_XOR_MULT_DOSStub_17a7 {
  strings:
    $key_17a7 = { 43 cf [2] 37 d7 [2] 70 d5 [2] 37 c4 [2] 79 c8 [2] 75 c2 [2] 62 c9 [2] 79 87 [2] 44 }

  condition:
    any of them
}