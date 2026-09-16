rule TTP_XOR_MULT_DOSStub_67b4 {
  strings:
    $key_67b4 = { 33 dc [2] 47 c4 [2] 00 c6 [2] 47 d7 [2] 09 db [2] 05 d1 [2] 12 da [2] 09 94 [2] 34 }

  condition:
    any of them
}