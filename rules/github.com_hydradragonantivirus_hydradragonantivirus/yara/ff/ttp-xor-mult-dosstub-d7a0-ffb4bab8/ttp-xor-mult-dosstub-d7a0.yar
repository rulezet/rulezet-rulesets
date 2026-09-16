rule TTP_XOR_MULT_DOSStub_d7a0 {
  strings:
    $key_d7a0 = { 83 c8 [2] f7 d0 [2] b0 d2 [2] f7 c3 [2] b9 cf [2] b5 c5 [2] a2 ce [2] b9 80 [2] 84 }

  condition:
    any of them
}