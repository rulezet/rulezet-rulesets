rule TTP_XOR_MULT_DOSStub_2394 {
  strings:
    $key_2394 = { 77 fc [2] 03 e4 [2] 44 e6 [2] 03 f7 [2] 4d fb [2] 41 f1 [2] 56 fa [2] 4d b4 [2] 70 }

  condition:
    any of them
}