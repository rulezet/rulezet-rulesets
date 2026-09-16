rule TTP_XOR_MULT_DOSStub_0795 {
  strings:
    $key_0795 = { 53 fd [2] 27 e5 [2] 60 e7 [2] 27 f6 [2] 69 fa [2] 65 f0 [2] 72 fb [2] 69 b5 [2] 54 }

  condition:
    any of them
}