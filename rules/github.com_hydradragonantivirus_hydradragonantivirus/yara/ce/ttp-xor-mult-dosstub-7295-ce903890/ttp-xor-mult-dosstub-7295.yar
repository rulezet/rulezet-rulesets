rule TTP_XOR_MULT_DOSStub_7295 {
  strings:
    $key_7295 = { 26 fd [2] 52 e5 [2] 15 e7 [2] 52 f6 [2] 1c fa [2] 10 f0 [2] 07 fb [2] 1c b5 [2] 21 }

  condition:
    any of them
}