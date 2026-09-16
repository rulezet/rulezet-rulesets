rule TTP_XOR_MULT_DOSStub_4799 {
  strings:
    $key_4799 = { 13 f1 [2] 67 e9 [2] 20 eb [2] 67 fa [2] 29 f6 [2] 25 fc [2] 32 f7 [2] 29 b9 [2] 14 }

  condition:
    any of them
}