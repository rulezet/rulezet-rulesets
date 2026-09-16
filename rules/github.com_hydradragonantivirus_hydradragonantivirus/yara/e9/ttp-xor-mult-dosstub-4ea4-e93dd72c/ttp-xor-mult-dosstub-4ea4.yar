rule TTP_XOR_MULT_DOSStub_4ea4 {
  strings:
    $key_4ea4 = { 1a cc [2] 6e d4 [2] 29 d6 [2] 6e c7 [2] 20 cb [2] 2c c1 [2] 3b ca [2] 20 84 [2] 1d }

  condition:
    any of them
}