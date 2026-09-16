rule TTP_XOR_MULT_DOSStub_a4a0 {
  strings:
    $key_a4a0 = { f0 c8 [2] 84 d0 [2] c3 d2 [2] 84 c3 [2] ca cf [2] c6 c5 [2] d1 ce [2] ca 80 [2] f7 }

  condition:
    any of them
}