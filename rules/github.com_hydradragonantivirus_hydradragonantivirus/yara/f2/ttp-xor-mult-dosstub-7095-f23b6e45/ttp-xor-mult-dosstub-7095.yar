rule TTP_XOR_MULT_DOSStub_7095 {
  strings:
    $key_7095 = { 24 fd [2] 50 e5 [2] 17 e7 [2] 50 f6 [2] 1e fa [2] 12 f0 [2] 05 fb [2] 1e b5 [2] 23 }

  condition:
    any of them
}