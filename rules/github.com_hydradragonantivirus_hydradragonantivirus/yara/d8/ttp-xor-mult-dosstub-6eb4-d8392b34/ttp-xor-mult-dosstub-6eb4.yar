rule TTP_XOR_MULT_DOSStub_6eb4 {
  strings:
    $key_6eb4 = { 3a dc [2] 4e c4 [2] 09 c6 [2] 4e d7 [2] 00 db [2] 0c d1 [2] 1b da [2] 00 94 [2] 3d }

  condition:
    any of them
}