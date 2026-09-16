rule TTP_XOR_MULT_DOSStub_16a7 {
  strings:
    $key_16a7 = { 42 cf [2] 36 d7 [2] 71 d5 [2] 36 c4 [2] 78 c8 [2] 74 c2 [2] 63 c9 [2] 78 87 [2] 45 }

  condition:
    any of them
}