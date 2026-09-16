rule TTP_XOR_MULT_DOSStub_12a0 {
  strings:
    $key_12a0 = { 46 c8 [2] 32 d0 [2] 75 d2 [2] 32 c3 [2] 7c cf [2] 70 c5 [2] 67 ce [2] 7c 80 [2] 41 }

  condition:
    any of them
}