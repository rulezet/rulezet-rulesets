rule TTP_XOR_MULT_DOSStub_52b4 {
  strings:
    $key_52b4 = { 06 dc [2] 72 c4 [2] 35 c6 [2] 72 d7 [2] 3c db [2] 30 d1 [2] 27 da [2] 3c 94 [2] 01 }

  condition:
    any of them
}