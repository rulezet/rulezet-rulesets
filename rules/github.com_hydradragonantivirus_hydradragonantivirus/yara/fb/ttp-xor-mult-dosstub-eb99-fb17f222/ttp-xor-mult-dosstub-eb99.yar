rule TTP_XOR_MULT_DOSStub_eb99 {
  strings:
    $key_eb99 = { bf f1 [2] cb e9 [2] 8c eb [2] cb fa [2] 85 f6 [2] 89 fc [2] 9e f7 [2] 85 b9 [2] b8 }

  condition:
    any of them
}