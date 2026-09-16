rule TTP_XOR_MULT_DOSStub_c0b4 {
  strings:
    $key_c0b4 = { 94 dc [2] e0 c4 [2] a7 c6 [2] e0 d7 [2] ae db [2] a2 d1 [2] b5 da [2] ae 94 [2] 93 }

  condition:
    any of them
}