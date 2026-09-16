rule TTP_XOR_MULT_DOSStub_6d99 {
  strings:
    $key_6d99 = { 39 f1 [2] 4d e9 [2] 0a eb [2] 4d fa [2] 03 f6 [2] 0f fc [2] 18 f7 [2] 03 b9 [2] 3e }

  condition:
    any of them
}