rule TTP_XOR_MULT_DOSStub_d2a7 {
  strings:
    $key_d2a7 = { 86 cf [2] f2 d7 [2] b5 d5 [2] f2 c4 [2] bc c8 [2] b0 c2 [2] a7 c9 [2] bc 87 [2] 81 }

  condition:
    any of them
}