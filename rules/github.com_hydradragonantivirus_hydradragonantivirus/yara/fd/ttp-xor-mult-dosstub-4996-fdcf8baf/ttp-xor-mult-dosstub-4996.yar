rule TTP_XOR_MULT_DOSStub_4996 {
  strings:
    $key_4996 = { 1d fe [2] 69 e6 [2] 2e e4 [2] 69 f5 [2] 27 f9 [2] 2b f3 [2] 3c f8 [2] 27 b6 [2] 1a }

  condition:
    any of them
}