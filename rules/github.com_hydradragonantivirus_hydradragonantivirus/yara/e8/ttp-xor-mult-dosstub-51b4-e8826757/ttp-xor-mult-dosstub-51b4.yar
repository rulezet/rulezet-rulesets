rule TTP_XOR_MULT_DOSStub_51b4 {
  strings:
    $key_51b4 = { 05 dc [2] 71 c4 [2] 36 c6 [2] 71 d7 [2] 3f db [2] 33 d1 [2] 24 da [2] 3f 94 [2] 02 }

  condition:
    any of them
}