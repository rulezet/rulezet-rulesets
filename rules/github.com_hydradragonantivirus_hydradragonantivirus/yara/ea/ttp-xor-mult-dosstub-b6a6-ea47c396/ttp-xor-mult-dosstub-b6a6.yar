rule TTP_XOR_MULT_DOSStub_b6a6 {
  strings:
    $key_b6a6 = { e2 ce [2] 96 d6 [2] d1 d4 [2] 96 c5 [2] d8 c9 [2] d4 c3 [2] c3 c8 [2] d8 86 [2] e5 }

  condition:
    any of them
}