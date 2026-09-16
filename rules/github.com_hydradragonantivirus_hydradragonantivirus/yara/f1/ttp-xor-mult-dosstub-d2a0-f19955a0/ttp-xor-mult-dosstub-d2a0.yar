rule TTP_XOR_MULT_DOSStub_d2a0 {
  strings:
    $key_d2a0 = { 86 c8 [2] f2 d0 [2] b5 d2 [2] f2 c3 [2] bc cf [2] b0 c5 [2] a7 ce [2] bc 80 [2] 81 }

  condition:
    any of them
}