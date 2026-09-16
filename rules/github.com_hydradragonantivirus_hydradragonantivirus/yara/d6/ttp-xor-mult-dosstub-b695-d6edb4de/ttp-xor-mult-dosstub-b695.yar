rule TTP_XOR_MULT_DOSStub_b695 {
  strings:
    $key_b695 = { e2 fd [2] 96 e5 [2] d1 e7 [2] 96 f6 [2] d8 fa [2] d4 f0 [2] c3 fb [2] d8 b5 [2] e5 }

  condition:
    any of them
}