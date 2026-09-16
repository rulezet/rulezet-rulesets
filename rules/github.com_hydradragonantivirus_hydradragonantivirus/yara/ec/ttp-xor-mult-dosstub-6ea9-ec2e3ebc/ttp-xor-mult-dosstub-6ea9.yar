rule TTP_XOR_MULT_DOSStub_6ea9 {
  strings:
    $key_6ea9 = { 3a c1 [2] 4e d9 [2] 09 db [2] 4e ca [2] 00 c6 [2] 0c cc [2] 1b c7 [2] 00 89 [2] 3d }

  condition:
    any of them
}