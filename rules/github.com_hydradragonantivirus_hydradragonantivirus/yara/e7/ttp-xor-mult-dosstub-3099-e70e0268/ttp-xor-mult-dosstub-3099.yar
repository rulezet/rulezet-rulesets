rule TTP_XOR_MULT_DOSStub_3099 {
  strings:
    $key_3099 = { 64 f1 [2] 10 e9 [2] 57 eb [2] 10 fa [2] 5e f6 [2] 52 fc [2] 45 f7 [2] 5e b9 [2] 63 }

  condition:
    any of them
}