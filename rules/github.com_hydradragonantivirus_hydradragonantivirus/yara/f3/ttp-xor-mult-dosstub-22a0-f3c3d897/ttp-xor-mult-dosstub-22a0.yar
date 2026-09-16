rule TTP_XOR_MULT_DOSStub_22a0 {
  strings:
    $key_22a0 = { 76 c8 [2] 02 d0 [2] 45 d2 [2] 02 c3 [2] 4c cf [2] 40 c5 [2] 57 ce [2] 4c 80 [2] 71 }

  condition:
    any of them
}