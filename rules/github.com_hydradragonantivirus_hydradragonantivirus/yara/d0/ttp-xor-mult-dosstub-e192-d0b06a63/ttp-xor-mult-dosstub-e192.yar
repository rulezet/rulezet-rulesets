rule TTP_XOR_MULT_DOSStub_e192 {
  strings:
    $key_e192 = { b5 fa [2] c1 e2 [2] 86 e0 [2] c1 f1 [2] 8f fd [2] 83 f7 [2] 94 fc [2] 8f b2 [2] b2 }

  condition:
    any of them
}