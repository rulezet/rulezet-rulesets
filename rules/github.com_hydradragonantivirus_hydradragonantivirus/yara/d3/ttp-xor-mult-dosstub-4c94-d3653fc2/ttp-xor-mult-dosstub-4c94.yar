rule TTP_XOR_MULT_DOSStub_4c94 {
  strings:
    $key_4c94 = { 18 fc [2] 6c e4 [2] 2b e6 [2] 6c f7 [2] 22 fb [2] 2e f1 [2] 39 fa [2] 22 b4 [2] 1f }

  condition:
    any of them
}