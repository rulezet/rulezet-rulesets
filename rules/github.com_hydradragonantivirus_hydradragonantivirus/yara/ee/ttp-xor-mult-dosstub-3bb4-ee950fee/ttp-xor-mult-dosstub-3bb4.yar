rule TTP_XOR_MULT_DOSStub_3bb4 {
  strings:
    $key_3bb4 = { 6f dc [2] 1b c4 [2] 5c c6 [2] 1b d7 [2] 55 db [2] 59 d1 [2] 4e da [2] 55 94 [2] 68 }

  condition:
    any of them
}