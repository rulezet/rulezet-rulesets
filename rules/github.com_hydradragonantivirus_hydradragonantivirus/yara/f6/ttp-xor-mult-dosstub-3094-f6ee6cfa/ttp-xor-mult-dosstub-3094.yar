rule TTP_XOR_MULT_DOSStub_3094 {
  strings:
    $key_3094 = { 64 fc [2] 10 e4 [2] 57 e6 [2] 10 f7 [2] 5e fb [2] 52 f1 [2] 45 fa [2] 5e b4 [2] 63 }

  condition:
    any of them
}