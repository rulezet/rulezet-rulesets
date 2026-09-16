rule TTP_XOR_MULT_DOSStub_b2a6 {
  strings:
    $key_b2a6 = { e6 ce [2] 92 d6 [2] d5 d4 [2] 92 c5 [2] dc c9 [2] d0 c3 [2] c7 c8 [2] dc 86 [2] e1 }

  condition:
    any of them
}