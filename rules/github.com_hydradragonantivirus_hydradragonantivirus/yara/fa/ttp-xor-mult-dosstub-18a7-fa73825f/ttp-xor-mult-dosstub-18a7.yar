rule TTP_XOR_MULT_DOSStub_18a7 {
  strings:
    $key_18a7 = { 4c cf [2] 38 d7 [2] 7f d5 [2] 38 c4 [2] 76 c8 [2] 7a c2 [2] 6d c9 [2] 76 87 [2] 4b }

  condition:
    any of them
}