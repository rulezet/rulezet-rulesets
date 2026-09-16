rule TTP_XOR_MULT_DOSStub_06a0 {
  strings:
    $key_06a0 = { 52 c8 [2] 26 d0 [2] 61 d2 [2] 26 c3 [2] 68 cf [2] 64 c5 [2] 73 ce [2] 68 80 [2] 55 }

  condition:
    any of them
}