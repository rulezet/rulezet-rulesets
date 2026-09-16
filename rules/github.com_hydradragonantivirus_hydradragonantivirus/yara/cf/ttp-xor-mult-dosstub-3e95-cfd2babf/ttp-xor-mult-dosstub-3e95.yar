rule TTP_XOR_MULT_DOSStub_3e95 {
  strings:
    $key_3e95 = { 6a fd [2] 1e e5 [2] 59 e7 [2] 1e f6 [2] 50 fa [2] 5c f0 [2] 4b fb [2] 50 b5 [2] 6d }

  condition:
    any of them
}