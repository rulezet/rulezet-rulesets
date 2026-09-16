rule TTP_XOR_MULT_DOSStub_8599 {
  strings:
    $key_8599 = { d1 f1 [2] a5 e9 [2] e2 eb [2] a5 fa [2] eb f6 [2] e7 fc [2] f0 f7 [2] eb b9 [2] d6 }

  condition:
    any of them
}