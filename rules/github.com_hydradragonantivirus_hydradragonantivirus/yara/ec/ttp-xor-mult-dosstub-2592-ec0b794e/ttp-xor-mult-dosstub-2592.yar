rule TTP_XOR_MULT_DOSStub_2592 {
  strings:
    $key_2592 = { 71 fa [2] 05 e2 [2] 42 e0 [2] 05 f1 [2] 4b fd [2] 47 f7 [2] 50 fc [2] 4b b2 [2] 76 }

  condition:
    any of them
}