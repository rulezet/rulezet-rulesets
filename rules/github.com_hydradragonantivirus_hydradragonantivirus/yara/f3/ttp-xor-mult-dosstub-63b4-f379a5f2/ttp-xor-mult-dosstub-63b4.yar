rule TTP_XOR_MULT_DOSStub_63b4 {
  strings:
    $key_63b4 = { 37 dc [2] 43 c4 [2] 04 c6 [2] 43 d7 [2] 0d db [2] 01 d1 [2] 16 da [2] 0d 94 [2] 30 }

  condition:
    any of them
}