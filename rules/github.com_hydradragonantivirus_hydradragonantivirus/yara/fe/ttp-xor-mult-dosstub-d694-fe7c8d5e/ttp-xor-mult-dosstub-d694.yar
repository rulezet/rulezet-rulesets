rule TTP_XOR_MULT_DOSStub_d694 {
  strings:
    $key_d694 = { 82 fc [2] f6 e4 [2] b1 e6 [2] f6 f7 [2] b8 fb [2] b4 f1 [2] a3 fa [2] b8 b4 [2] 85 }

  condition:
    any of them
}