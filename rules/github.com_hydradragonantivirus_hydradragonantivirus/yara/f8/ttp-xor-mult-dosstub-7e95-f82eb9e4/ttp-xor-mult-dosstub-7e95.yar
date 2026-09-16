rule TTP_XOR_MULT_DOSStub_7e95 {
  strings:
    $key_7e95 = { 2a fd [2] 5e e5 [2] 19 e7 [2] 5e f6 [2] 10 fa [2] 1c f0 [2] 0b fb [2] 10 b5 [2] 2d }

  condition:
    any of them
}