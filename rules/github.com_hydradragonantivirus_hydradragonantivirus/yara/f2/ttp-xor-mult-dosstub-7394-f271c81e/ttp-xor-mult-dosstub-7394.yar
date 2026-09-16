rule TTP_XOR_MULT_DOSStub_7394 {
  strings:
    $key_7394 = { 27 fc [2] 53 e4 [2] 14 e6 [2] 53 f7 [2] 1d fb [2] 11 f1 [2] 06 fa [2] 1d b4 [2] 20 }

  condition:
    any of them
}