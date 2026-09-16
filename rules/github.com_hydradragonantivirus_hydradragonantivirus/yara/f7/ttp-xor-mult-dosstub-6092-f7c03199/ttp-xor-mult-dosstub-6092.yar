rule TTP_XOR_MULT_DOSStub_6092 {
  strings:
    $key_6092 = { 34 fa [2] 40 e2 [2] 07 e0 [2] 40 f1 [2] 0e fd [2] 02 f7 [2] 15 fc [2] 0e b2 [2] 33 }

  condition:
    any of them
}