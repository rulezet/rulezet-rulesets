rule TTP_XOR_MULT_DOSStub_27a0 {
  strings:
    $key_27a0 = { 73 c8 [2] 07 d0 [2] 40 d2 [2] 07 c3 [2] 49 cf [2] 45 c5 [2] 52 ce [2] 49 80 [2] 74 }

  condition:
    any of them
}