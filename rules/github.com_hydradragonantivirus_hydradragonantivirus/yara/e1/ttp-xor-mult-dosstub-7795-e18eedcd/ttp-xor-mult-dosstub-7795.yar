rule TTP_XOR_MULT_DOSStub_7795 {
  strings:
    $key_7795 = { 23 fd [2] 57 e5 [2] 10 e7 [2] 57 f6 [2] 19 fa [2] 15 f0 [2] 02 fb [2] 19 b5 [2] 24 }

  condition:
    any of them
}