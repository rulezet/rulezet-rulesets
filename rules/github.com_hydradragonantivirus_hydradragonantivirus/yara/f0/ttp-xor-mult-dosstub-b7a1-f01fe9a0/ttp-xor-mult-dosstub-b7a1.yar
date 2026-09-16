rule TTP_XOR_MULT_DOSStub_b7a1 {
  strings:
    $key_b7a1 = { e3 c9 [2] 97 d1 [2] d0 d3 [2] 97 c2 [2] d9 ce [2] d5 c4 [2] c2 cf [2] d9 81 [2] e4 }

  condition:
    any of them
}