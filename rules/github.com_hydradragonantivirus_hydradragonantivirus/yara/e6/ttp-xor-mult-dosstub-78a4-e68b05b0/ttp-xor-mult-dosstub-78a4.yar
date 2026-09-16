rule TTP_XOR_MULT_DOSStub_78a4 {
  strings:
    $key_78a4 = { 2c cc [2] 58 d4 [2] 1f d6 [2] 58 c7 [2] 16 cb [2] 1a c1 [2] 0d ca [2] 16 84 [2] 2b }

  condition:
    any of them
}