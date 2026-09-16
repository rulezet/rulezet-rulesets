rule TTP_XOR_MULT_DOSStub_4399 {
  strings:
    $key_4399 = { 17 f1 [2] 63 e9 [2] 24 eb [2] 63 fa [2] 2d f6 [2] 21 fc [2] 36 f7 [2] 2d b9 [2] 10 }

  condition:
    any of them
}