rule TTP_XOR_MULT_DOSStub_10b4 {
  strings:
    $key_10b4 = { 44 dc [2] 30 c4 [2] 77 c6 [2] 30 d7 [2] 7e db [2] 72 d1 [2] 65 da [2] 7e 94 [2] 43 }

  condition:
    any of them
}