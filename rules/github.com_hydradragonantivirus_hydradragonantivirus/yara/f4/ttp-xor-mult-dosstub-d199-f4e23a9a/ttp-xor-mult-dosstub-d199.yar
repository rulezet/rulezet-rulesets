rule TTP_XOR_MULT_DOSStub_d199 {
  strings:
    $key_d199 = { 85 f1 [2] f1 e9 [2] b6 eb [2] f1 fa [2] bf f6 [2] b3 fc [2] a4 f7 [2] bf b9 [2] 82 }

  condition:
    any of them
}