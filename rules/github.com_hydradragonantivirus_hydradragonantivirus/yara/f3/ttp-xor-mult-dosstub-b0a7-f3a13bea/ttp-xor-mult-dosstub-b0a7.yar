rule TTP_XOR_MULT_DOSStub_b0a7 {
  strings:
    $key_b0a7 = { e4 cf [2] 90 d7 [2] d7 d5 [2] 90 c4 [2] de c8 [2] d2 c2 [2] c5 c9 [2] de 87 [2] e3 }

  condition:
    any of them
}