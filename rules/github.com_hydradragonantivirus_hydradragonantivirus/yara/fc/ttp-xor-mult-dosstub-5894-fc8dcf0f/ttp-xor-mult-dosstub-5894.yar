rule TTP_XOR_MULT_DOSStub_5894 {
  strings:
    $key_5894 = { 0c fc [2] 78 e4 [2] 3f e6 [2] 78 f7 [2] 36 fb [2] 3a f1 [2] 2d fa [2] 36 b4 [2] 0b }

  condition:
    any of them
}