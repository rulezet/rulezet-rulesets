rule TTP_XOR_MULT_DOSStub_4394 {
  strings:
    $key_4394 = { 17 fc [2] 63 e4 [2] 24 e6 [2] 63 f7 [2] 2d fb [2] 21 f1 [2] 36 fa [2] 2d b4 [2] 10 }

  condition:
    any of them
}