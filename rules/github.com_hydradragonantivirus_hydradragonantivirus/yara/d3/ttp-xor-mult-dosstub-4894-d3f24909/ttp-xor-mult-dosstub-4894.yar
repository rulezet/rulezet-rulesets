rule TTP_XOR_MULT_DOSStub_4894 {
  strings:
    $key_4894 = { 1c fc [2] 68 e4 [2] 2f e6 [2] 68 f7 [2] 26 fb [2] 2a f1 [2] 3d fa [2] 26 b4 [2] 1b }

  condition:
    any of them
}