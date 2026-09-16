rule TTP_XOR_MULT_DOSStub_b7a7 {
  strings:
    $key_b7a7 = { e3 cf [2] 97 d7 [2] d0 d5 [2] 97 c4 [2] d9 c8 [2] d5 c2 [2] c2 c9 [2] d9 87 [2] e4 }

  condition:
    any of them
}