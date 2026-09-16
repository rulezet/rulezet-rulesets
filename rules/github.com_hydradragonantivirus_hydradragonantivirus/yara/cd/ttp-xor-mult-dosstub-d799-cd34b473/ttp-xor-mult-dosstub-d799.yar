rule TTP_XOR_MULT_DOSStub_d799 {
  strings:
    $key_d799 = { 83 f1 [2] f7 e9 [2] b0 eb [2] f7 fa [2] b9 f6 [2] b5 fc [2] a2 f7 [2] b9 b9 [2] 84 }

  condition:
    any of them
}