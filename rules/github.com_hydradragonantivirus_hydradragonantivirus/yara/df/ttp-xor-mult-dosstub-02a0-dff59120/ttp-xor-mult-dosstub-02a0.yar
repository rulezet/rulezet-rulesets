rule TTP_XOR_MULT_DOSStub_02a0 {
  strings:
    $key_02a0 = { 56 c8 [2] 22 d0 [2] 65 d2 [2] 22 c3 [2] 6c cf [2] 60 c5 [2] 77 ce [2] 6c 80 [2] 51 }

  condition:
    any of them
}