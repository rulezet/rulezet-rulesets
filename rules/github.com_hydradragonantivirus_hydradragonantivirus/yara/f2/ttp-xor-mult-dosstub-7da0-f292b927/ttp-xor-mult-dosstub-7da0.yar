rule TTP_XOR_MULT_DOSStub_7da0 {
  strings:
    $key_7da0 = { 29 c8 [2] 5d d0 [2] 1a d2 [2] 5d c3 [2] 13 cf [2] 1f c5 [2] 08 ce [2] 13 80 [2] 2e }

  condition:
    any of them
}