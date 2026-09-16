rule TTP_XOR_MULT_DOSStub_6eb5 {
  strings:
    $key_6eb5 = { 3a dd [2] 4e c5 [2] 09 c7 [2] 4e d6 [2] 00 da [2] 0c d0 [2] 1b db [2] 00 95 [2] 3d }

  condition:
    any of them
}