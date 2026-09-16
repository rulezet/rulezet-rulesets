rule TTP_XOR_MULT_DOSStub_21b4 {
  strings:
    $key_21b4 = { 75 dc [2] 01 c4 [2] 46 c6 [2] 01 d7 [2] 4f db [2] 43 d1 [2] 54 da [2] 4f 94 [2] 72 }

  condition:
    any of them
}