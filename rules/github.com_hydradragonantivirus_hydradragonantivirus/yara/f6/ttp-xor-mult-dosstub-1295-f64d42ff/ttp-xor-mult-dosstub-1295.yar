rule TTP_XOR_MULT_DOSStub_1295 {
  strings:
    $key_1295 = { 46 fd [2] 32 e5 [2] 75 e7 [2] 32 f6 [2] 7c fa [2] 70 f0 [2] 67 fb [2] 7c b5 [2] 41 }

  condition:
    any of them
}