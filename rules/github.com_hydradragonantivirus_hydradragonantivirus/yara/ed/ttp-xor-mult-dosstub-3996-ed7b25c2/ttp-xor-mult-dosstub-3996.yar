rule TTP_XOR_MULT_DOSStub_3996 {
  strings:
    $key_3996 = { 6d fe [2] 19 e6 [2] 5e e4 [2] 19 f5 [2] 57 f9 [2] 5b f3 [2] 4c f8 [2] 57 b6 [2] 6a }

  condition:
    any of them
}