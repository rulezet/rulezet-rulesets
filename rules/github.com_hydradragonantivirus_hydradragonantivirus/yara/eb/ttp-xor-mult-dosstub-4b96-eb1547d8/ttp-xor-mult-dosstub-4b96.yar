rule TTP_XOR_MULT_DOSStub_4b96 {
  strings:
    $key_4b96 = { 1f fe [2] 6b e6 [2] 2c e4 [2] 6b f5 [2] 25 f9 [2] 29 f3 [2] 3e f8 [2] 25 b6 [2] 18 }

  condition:
    any of them
}