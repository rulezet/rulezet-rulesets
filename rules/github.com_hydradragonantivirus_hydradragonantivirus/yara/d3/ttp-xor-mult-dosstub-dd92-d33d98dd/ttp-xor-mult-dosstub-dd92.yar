rule TTP_XOR_MULT_DOSStub_dd92 {
  strings:
    $key_dd92 = { 89 fa [2] fd e2 [2] ba e0 [2] fd f1 [2] b3 fd [2] bf f7 [2] a8 fc [2] b3 b2 [2] 8e }

  condition:
    any of them
}