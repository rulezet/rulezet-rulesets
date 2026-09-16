rule TTP_XOR_MULT_DOSStub_44a7 {
  strings:
    $key_44a7 = { 10 cf [2] 64 d7 [2] 23 d5 [2] 64 c4 [2] 2a c8 [2] 26 c2 [2] 31 c9 [2] 2a 87 [2] 17 }

  condition:
    any of them
}