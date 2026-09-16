rule TTP_XOR_MULT_DOSStub_e0b4 {
  strings:
    $key_e0b4 = { b4 dc [2] c0 c4 [2] 87 c6 [2] c0 d7 [2] 8e db [2] 82 d1 [2] 95 da [2] 8e 94 [2] b3 }

  condition:
    any of them
}