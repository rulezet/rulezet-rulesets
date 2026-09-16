rule TTP_XOR_MULT_DOSStub_26b4 {
  strings:
    $key_26b4 = { 72 dc [2] 06 c4 [2] 41 c6 [2] 06 d7 [2] 48 db [2] 44 d1 [2] 53 da [2] 48 94 [2] 75 }

  condition:
    any of them
}