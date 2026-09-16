rule TTP_XOR_MULT_DOSStub_8699 {
  strings:
    $key_8699 = { d2 f1 [2] a6 e9 [2] e1 eb [2] a6 fa [2] e8 f6 [2] e4 fc [2] f3 f7 [2] e8 b9 [2] d5 }

  condition:
    any of them
}