rule TTP_XOR_MULT_DOSStub_c3a0 {
  strings:
    $key_c3a0 = { 97 c8 [2] e3 d0 [2] a4 d2 [2] e3 c3 [2] ad cf [2] a1 c5 [2] b6 ce [2] ad 80 [2] 90 }

  condition:
    any of them
}