rule TTP_XOR_MULT_DOSStub_b0b9 {
  strings:
    $key_b0b9 = { e4 d1 [2] 90 c9 [2] d7 cb [2] 90 da [2] de d6 [2] d2 dc [2] c5 d7 [2] de 99 [2] e3 }

  condition:
    any of them
}