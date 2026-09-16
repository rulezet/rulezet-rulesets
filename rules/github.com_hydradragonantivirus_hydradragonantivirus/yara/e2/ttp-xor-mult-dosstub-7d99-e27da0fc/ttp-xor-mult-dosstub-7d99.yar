rule TTP_XOR_MULT_DOSStub_7d99 {
  strings:
    $key_7d99 = { 29 f1 [2] 5d e9 [2] 1a eb [2] 5d fa [2] 13 f6 [2] 1f fc [2] 08 f7 [2] 13 b9 [2] 2e }

  condition:
    any of them
}