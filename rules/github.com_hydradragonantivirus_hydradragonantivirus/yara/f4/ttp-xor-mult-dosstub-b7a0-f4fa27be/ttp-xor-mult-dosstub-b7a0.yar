rule TTP_XOR_MULT_DOSStub_b7a0 {
  strings:
    $key_b7a0 = { e3 c8 [2] 97 d0 [2] d0 d2 [2] 97 c3 [2] d9 cf [2] d5 c5 [2] c2 ce [2] d9 80 [2] e4 }

  condition:
    any of them
}