rule TTP_XOR_MULT_DOSStub_66a0 {
  strings:
    $key_66a0 = { 32 c8 [2] 46 d0 [2] 01 d2 [2] 46 c3 [2] 08 cf [2] 04 c5 [2] 13 ce [2] 08 80 [2] 35 }

  condition:
    any of them
}