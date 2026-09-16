rule TTP_XOR_MULT_DOSStub_c695 {
  strings:
    $key_c695 = { 92 fd [2] e6 e5 [2] a1 e7 [2] e6 f6 [2] a8 fa [2] a4 f0 [2] b3 fb [2] a8 b5 [2] 95 }

  condition:
    any of them
}