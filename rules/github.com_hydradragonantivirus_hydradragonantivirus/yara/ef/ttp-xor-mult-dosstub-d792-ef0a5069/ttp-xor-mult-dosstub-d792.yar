rule TTP_XOR_MULT_DOSStub_d792 {
  strings:
    $key_d792 = { 83 fa [2] f7 e2 [2] b0 e0 [2] f7 f1 [2] b9 fd [2] b5 f7 [2] a2 fc [2] b9 b2 [2] 84 }

  condition:
    any of them
}