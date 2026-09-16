rule TTP_XOR_MULT_DOSStub_3c94 {
  strings:
    $key_3c94 = { 68 fc [2] 1c e4 [2] 5b e6 [2] 1c f7 [2] 52 fb [2] 5e f1 [2] 49 fa [2] 52 b4 [2] 6f }

  condition:
    any of them
}