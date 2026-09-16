rule TTP_XOR_MULT_DOSStub_3e96 {
  strings:
    $key_3e96 = { 6a fe [2] 1e e6 [2] 59 e4 [2] 1e f5 [2] 50 f9 [2] 5c f3 [2] 4b f8 [2] 50 b6 [2] 6d }

  condition:
    any of them
}