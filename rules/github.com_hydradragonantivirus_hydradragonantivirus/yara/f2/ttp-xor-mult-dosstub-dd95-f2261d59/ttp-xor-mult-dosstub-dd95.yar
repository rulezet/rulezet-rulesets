rule TTP_XOR_MULT_DOSStub_dd95 {
  strings:
    $key_dd95 = { 89 fd [2] fd e5 [2] ba e7 [2] fd f6 [2] b3 fa [2] bf f0 [2] a8 fb [2] b3 b5 [2] 8e }

  condition:
    any of them
}