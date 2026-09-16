rule TTP_XOR_MULT_DOSStub_0e95 {
  strings:
    $key_0e95 = { 5a fd [2] 2e e5 [2] 69 e7 [2] 2e f6 [2] 60 fa [2] 6c f0 [2] 7b fb [2] 60 b5 [2] 5d }

  condition:
    any of them
}