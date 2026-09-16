rule TTP_XOR_MULT_DOSStub_b099 {
  strings:
    $key_b099 = { e4 f1 [2] 90 e9 [2] d7 eb [2] 90 fa [2] de f6 [2] d2 fc [2] c5 f7 [2] de b9 [2] e3 }

  condition:
    any of them
}