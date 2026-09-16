rule TTP_XOR_MULT_DOSStub_7194 {
  strings:
    $key_7194 = { 25 fc [2] 51 e4 [2] 16 e6 [2] 51 f7 [2] 1f fb [2] 13 f1 [2] 04 fa [2] 1f b4 [2] 22 }

  condition:
    any of them
}