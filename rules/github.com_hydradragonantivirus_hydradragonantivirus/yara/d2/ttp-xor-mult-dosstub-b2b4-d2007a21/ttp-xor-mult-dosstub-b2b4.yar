rule TTP_XOR_MULT_DOSStub_b2b4 {
  strings:
    $key_b2b4 = { e6 dc [2] 92 c4 [2] d5 c6 [2] 92 d7 [2] dc db [2] d0 d1 [2] c7 da [2] dc 94 [2] e1 }

  condition:
    any of them
}