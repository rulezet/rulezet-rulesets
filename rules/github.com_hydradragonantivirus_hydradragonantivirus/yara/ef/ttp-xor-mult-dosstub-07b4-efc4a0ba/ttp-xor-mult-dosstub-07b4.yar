rule TTP_XOR_MULT_DOSStub_07b4 {
  strings:
    $key_07b4 = { 53 dc [2] 27 c4 [2] 60 c6 [2] 27 d7 [2] 69 db [2] 65 d1 [2] 72 da [2] 69 94 [2] 54 }

  condition:
    any of them
}