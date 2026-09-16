rule TTP_XOR_MULT_DOSStub_2194 {
  strings:
    $key_2194 = { 75 fc [2] 01 e4 [2] 46 e6 [2] 01 f7 [2] 4f fb [2] 43 f1 [2] 54 fa [2] 4f b4 [2] 72 }

  condition:
    any of them
}