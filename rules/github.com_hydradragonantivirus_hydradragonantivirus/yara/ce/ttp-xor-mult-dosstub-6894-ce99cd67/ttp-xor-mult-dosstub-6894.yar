rule TTP_XOR_MULT_DOSStub_6894 {
  strings:
    $key_6894 = { 3c fc [2] 48 e4 [2] 0f e6 [2] 48 f7 [2] 06 fb [2] 0a f1 [2] 1d fa [2] 06 b4 [2] 3b }

  condition:
    any of them
}