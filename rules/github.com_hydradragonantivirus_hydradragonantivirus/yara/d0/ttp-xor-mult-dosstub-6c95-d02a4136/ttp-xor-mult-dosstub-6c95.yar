rule TTP_XOR_MULT_DOSStub_6c95 {
  strings:
    $key_6c95 = { 38 fd [2] 4c e5 [2] 0b e7 [2] 4c f6 [2] 02 fa [2] 0e f0 [2] 19 fb [2] 02 b5 [2] 3f }

  condition:
    any of them
}