rule TTP_XOR_MULT_DOSStub_c4a0 {
  strings:
    $key_c4a0 = { 90 c8 [2] e4 d0 [2] a3 d2 [2] e4 c3 [2] aa cf [2] a6 c5 [2] b1 ce [2] aa 80 [2] 97 }

  condition:
    any of them
}