rule TTP_XOR_MULT_DOSStub_5da0 {
  strings:
    $key_5da0 = { 09 c8 [2] 7d d0 [2] 3a d2 [2] 7d c3 [2] 33 cf [2] 3f c5 [2] 28 ce [2] 33 80 [2] 0e }

  condition:
    any of them
}