rule TTP_XOR_MULT_DOSStub_b794 {
  strings:
    $key_b794 = { e3 fc [2] 97 e4 [2] d0 e6 [2] 97 f7 [2] d9 fb [2] d5 f1 [2] c2 fa [2] d9 b4 [2] e4 }

  condition:
    any of them
}