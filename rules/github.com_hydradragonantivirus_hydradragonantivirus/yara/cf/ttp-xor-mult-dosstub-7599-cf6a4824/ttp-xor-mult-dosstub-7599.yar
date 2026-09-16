rule TTP_XOR_MULT_DOSStub_7599 {
  strings:
    $key_7599 = { 21 f1 [2] 55 e9 [2] 12 eb [2] 55 fa [2] 1b f6 [2] 17 fc [2] 00 f7 [2] 1b b9 [2] 26 }

  condition:
    any of them
}