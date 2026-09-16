rule TTP_XOR_MULT_DOSStub_e594 {
  strings:
    $key_e594 = { b1 fc [2] c5 e4 [2] 82 e6 [2] c5 f7 [2] 8b fb [2] 87 f1 [2] 90 fa [2] 8b b4 [2] b6 }

  condition:
    any of them
}