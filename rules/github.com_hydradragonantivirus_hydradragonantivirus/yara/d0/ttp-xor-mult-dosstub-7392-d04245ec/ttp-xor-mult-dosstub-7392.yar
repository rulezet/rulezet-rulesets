rule TTP_XOR_MULT_DOSStub_7392 {
  strings:
    $key_7392 = { 27 fa [2] 53 e2 [2] 14 e0 [2] 53 f1 [2] 1d fd [2] 11 f7 [2] 06 fc [2] 1d b2 [2] 20 }

  condition:
    any of them
}