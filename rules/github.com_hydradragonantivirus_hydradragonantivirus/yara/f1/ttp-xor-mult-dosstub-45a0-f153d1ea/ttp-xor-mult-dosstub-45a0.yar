rule TTP_XOR_MULT_DOSStub_45a0 {
  strings:
    $key_45a0 = { 11 c8 [2] 65 d0 [2] 22 d2 [2] 65 c3 [2] 2b cf [2] 27 c5 [2] 30 ce [2] 2b 80 [2] 16 }

  condition:
    any of them
}