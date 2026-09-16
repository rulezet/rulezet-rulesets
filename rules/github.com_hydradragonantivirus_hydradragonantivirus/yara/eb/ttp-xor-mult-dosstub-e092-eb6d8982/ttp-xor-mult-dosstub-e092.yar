rule TTP_XOR_MULT_DOSStub_e092 {
  strings:
    $key_e092 = { b4 fa [2] c0 e2 [2] 87 e0 [2] c0 f1 [2] 8e fd [2] 82 f7 [2] 95 fc [2] 8e b2 [2] b3 }

  condition:
    any of them
}