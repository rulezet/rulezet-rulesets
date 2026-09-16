rule TTP_XOR_MULT_DOSStub_3199 {
  strings:
    $key_3199 = { 65 f1 [2] 11 e9 [2] 56 eb [2] 11 fa [2] 5f f6 [2] 53 fc [2] 44 f7 [2] 5f b9 [2] 62 }

  condition:
    any of them
}