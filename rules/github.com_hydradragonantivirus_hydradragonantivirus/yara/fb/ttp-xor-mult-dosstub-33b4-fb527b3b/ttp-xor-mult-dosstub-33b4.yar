rule TTP_XOR_MULT_DOSStub_33b4 {
  strings:
    $key_33b4 = { 67 dc [2] 13 c4 [2] 54 c6 [2] 13 d7 [2] 5d db [2] 51 d1 [2] 46 da [2] 5d 94 [2] 60 }

  condition:
    any of them
}