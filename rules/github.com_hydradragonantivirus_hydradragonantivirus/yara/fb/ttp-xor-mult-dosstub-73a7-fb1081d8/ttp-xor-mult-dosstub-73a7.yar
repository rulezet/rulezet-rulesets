rule TTP_XOR_MULT_DOSStub_73a7 {
  strings:
    $key_73a7 = { 27 cf [2] 53 d7 [2] 14 d5 [2] 53 c4 [2] 1d c8 [2] 11 c2 [2] 06 c9 [2] 1d 87 [2] 20 }

  condition:
    any of them
}