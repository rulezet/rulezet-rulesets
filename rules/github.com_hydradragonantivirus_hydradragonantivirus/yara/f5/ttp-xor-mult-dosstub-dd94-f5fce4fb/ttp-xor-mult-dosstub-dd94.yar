rule TTP_XOR_MULT_DOSStub_dd94 {
  strings:
    $key_dd94 = { 89 fc [2] fd e4 [2] ba e6 [2] fd f7 [2] b3 fb [2] bf f1 [2] a8 fa [2] b3 b4 [2] 8e }

  condition:
    any of them
}