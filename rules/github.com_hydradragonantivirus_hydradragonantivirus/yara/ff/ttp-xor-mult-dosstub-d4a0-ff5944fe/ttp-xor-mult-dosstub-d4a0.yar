rule TTP_XOR_MULT_DOSStub_d4a0 {
  strings:
    $key_d4a0 = { 80 c8 [2] f4 d0 [2] b3 d2 [2] f4 c3 [2] ba cf [2] b6 c5 [2] a1 ce [2] ba 80 [2] 87 }

  condition:
    any of them
}