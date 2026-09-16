rule TTP_XOR_MULT_DOSStub_b699 {
  strings:
    $key_b699 = { e2 f1 [2] 96 e9 [2] d1 eb [2] 96 fa [2] d8 f6 [2] d4 fc [2] c3 f7 [2] d8 b9 [2] e5 }

  condition:
    any of them
}