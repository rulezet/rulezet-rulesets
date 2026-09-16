rule TTP_XOR_MULT_DOSStub_1e96 {
  strings:
    $key_1e96 = { 4a fe [2] 3e e6 [2] 79 e4 [2] 3e f5 [2] 70 f9 [2] 7c f3 [2] 6b f8 [2] 70 b6 [2] 4d }

  condition:
    any of them
}