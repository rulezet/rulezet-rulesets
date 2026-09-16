rule TTP_XOR_MULT_DOSStub_7094 {
  strings:
    $key_7094 = { 24 fc [2] 50 e4 [2] 17 e6 [2] 50 f7 [2] 1e fb [2] 12 f1 [2] 05 fa [2] 1e b4 [2] 23 }

  condition:
    any of them
}