rule TTP_XOR_MULT_DOSStub_0194 {
  strings:
    $key_0194 = { 55 fc [2] 21 e4 [2] 66 e6 [2] 21 f7 [2] 6f fb [2] 63 f1 [2] 74 fa [2] 6f b4 [2] 52 }

  condition:
    any of them
}