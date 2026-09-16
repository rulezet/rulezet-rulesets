rule TTP_XOR_MULT_DOSStub_4ea9 {
  strings:
    $key_4ea9 = { 1a c1 [2] 6e d9 [2] 29 db [2] 6e ca [2] 20 c6 [2] 2c cc [2] 3b c7 [2] 20 89 [2] 1d }

  condition:
    any of them
}