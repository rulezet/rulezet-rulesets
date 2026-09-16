rule TTP_XOR_MULT_DOSStub_5099 {
  strings:
    $key_5099 = { 04 f1 [2] 70 e9 [2] 37 eb [2] 70 fa [2] 3e f6 [2] 32 fc [2] 25 f7 [2] 3e b9 [2] 03 }

  condition:
    any of them
}