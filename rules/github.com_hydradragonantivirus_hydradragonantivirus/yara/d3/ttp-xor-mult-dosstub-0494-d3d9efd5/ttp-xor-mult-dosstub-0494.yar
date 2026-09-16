rule TTP_XOR_MULT_DOSStub_0494 {
  strings:
    $key_0494 = { 50 fc [2] 24 e4 [2] 63 e6 [2] 24 f7 [2] 6a fb [2] 66 f1 [2] 71 fa [2] 6a b4 [2] 57 }

  condition:
    any of them
}