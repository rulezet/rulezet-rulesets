rule TTP_XOR_MULT_DOSStub_04a0 {
  strings:
    $key_04a0 = { 50 c8 [2] 24 d0 [2] 63 d2 [2] 24 c3 [2] 6a cf [2] 66 c5 [2] 71 ce [2] 6a 80 [2] 57 }

  condition:
    any of them
}