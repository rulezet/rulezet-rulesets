rule TTP_XOR_MULT_DOSStub_76a0 {
  strings:
    $key_76a0 = { 22 c8 [2] 56 d0 [2] 11 d2 [2] 56 c3 [2] 18 cf [2] 14 c5 [2] 03 ce [2] 18 80 [2] 25 }

  condition:
    any of them
}