rule TTP_XOR_MULT_DOSStub_b092 {
  strings:
    $key_b092 = { e4 fa [2] 90 e2 [2] d7 e0 [2] 90 f1 [2] de fd [2] d2 f7 [2] c5 fc [2] de b2 [2] e3 }

  condition:
    any of them
}