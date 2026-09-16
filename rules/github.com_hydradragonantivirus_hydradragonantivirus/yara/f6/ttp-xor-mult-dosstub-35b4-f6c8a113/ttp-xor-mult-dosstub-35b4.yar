rule TTP_XOR_MULT_DOSStub_35b4 {
  strings:
    $key_35b4 = { 61 dc [2] 15 c4 [2] 52 c6 [2] 15 d7 [2] 5b db [2] 57 d1 [2] 40 da [2] 5b 94 [2] 66 }

  condition:
    any of them
}