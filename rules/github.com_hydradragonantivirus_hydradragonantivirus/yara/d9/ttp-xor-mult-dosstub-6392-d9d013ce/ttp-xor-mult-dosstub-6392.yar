rule TTP_XOR_MULT_DOSStub_6392 {
  strings:
    $key_6392 = { 37 fa [2] 43 e2 [2] 04 e0 [2] 43 f1 [2] 0d fd [2] 01 f7 [2] 16 fc [2] 0d b2 [2] 30 }

  condition:
    any of them
}