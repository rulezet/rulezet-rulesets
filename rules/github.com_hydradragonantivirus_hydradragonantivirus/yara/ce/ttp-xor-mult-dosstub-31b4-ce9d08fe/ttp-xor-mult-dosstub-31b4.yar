rule TTP_XOR_MULT_DOSStub_31b4 {
  strings:
    $key_31b4 = { 65 dc [2] 11 c4 [2] 56 c6 [2] 11 d7 [2] 5f db [2] 53 d1 [2] 44 da [2] 5f 94 [2] 62 }

  condition:
    any of them
}