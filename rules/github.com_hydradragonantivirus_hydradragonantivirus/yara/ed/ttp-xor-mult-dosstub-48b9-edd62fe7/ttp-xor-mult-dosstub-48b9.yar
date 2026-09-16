rule TTP_XOR_MULT_DOSStub_48b9 {
  strings:
    $key_48b9 = { 1c d1 [2] 68 c9 [2] 2f cb [2] 68 da [2] 26 d6 [2] 2a dc [2] 3d d7 [2] 26 99 [2] 1b }

  condition:
    any of them
}