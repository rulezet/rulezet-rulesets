rule TTP_XOR_MULT_DOSStub_e394 {
  strings:
    $key_e394 = { b7 fc [2] c3 e4 [2] 84 e6 [2] c3 f7 [2] 8d fb [2] 81 f1 [2] 96 fa [2] 8d b4 [2] b0 }

  condition:
    any of them
}