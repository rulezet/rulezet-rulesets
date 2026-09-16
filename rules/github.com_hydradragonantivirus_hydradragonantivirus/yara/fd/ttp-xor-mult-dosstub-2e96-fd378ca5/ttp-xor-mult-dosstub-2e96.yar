rule TTP_XOR_MULT_DOSStub_2e96 {
  strings:
    $key_2e96 = { 7a fe [2] 0e e6 [2] 49 e4 [2] 0e f5 [2] 40 f9 [2] 4c f3 [2] 5b f8 [2] 40 b6 [2] 7d }

  condition:
    any of them
}